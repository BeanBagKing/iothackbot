"""
Core jtagprobe functionality - SWD/JTAG debug interface probing via SEGGER J-Link.

Drives JLinkExe through generated command scripts to test whether a target's
on-chip debug interface is exposed, and classifies the access level:

    OPEN    - DP responds, CPU halts, memory reads return plausible data
    LOCKED  - DP responds, but memory reads fail or return readout-protection
              sentinel (0xFFFFFFFF). Indicates RDP / CRP / APPROTECT engaged.
    DEAD    - No DP response on any tested interface/speed. Debug fused off,
              pins not wired, or wrong target.

Separated from CLI logic for automation and chaining.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .interfaces import ToolInterface, ToolConfig, ToolResult


# JEP106 ARM manufacturer continuation/identity → vendor name.
# Key format: (continuation_count, identity_code)
JEP106_VENDORS: Dict[Tuple[int, int], str] = {
    (0, 0x20): "STMicroelectronics",
    (0, 0x15): "NXP",
    (0, 0x49): "Texas Instruments",
    (0, 0x17): "Texas Instruments",
    (0, 0x3B): "ARM",
    (0, 0x7F): "ARM",
    (4, 0x3B): "ARM",
    (4, 0x44): "Nordic Semiconductor",
    (0, 0x44): "Nordic Semiconductor",
    (0, 0x1F): "Atmel/Microchip",
    (0, 0x1B): "Cypress/Infineon",
    (0, 0x09): "Infineon",
    (0, 0x4B): "Espressif",
    (0, 0x6B): "Silicon Labs",
    (0, 0x21): "Renesas",
}

# Generic ARM device profiles to try when target is unknown.
GENERIC_DEVICES = ["Cortex-M0", "Cortex-M3", "Cortex-M4", "Cortex-M7", "Cortex-A9"]

# Common flash bases by vendor identity, used for the memory-read sanity check.
VENDOR_FLASH_BASES: Dict[str, List[int]] = {
    "STMicroelectronics": [0x08000000],
    "NXP": [0x00000000, 0x10000000],
    "Nordic Semiconductor": [0x00000000, 0x10001000],
    "Texas Instruments": [0x00000000],
    "Silicon Labs": [0x00000000],
    "Atmel/Microchip": [0x00000000],
    "Espressif": [0x40000000],
    "Renesas": [0x00000000],
}

DEFAULT_FLASH_BASES = [0x00000000, 0x08000000]
SRAM_PLAUSIBLE_RANGES = [
    (0x20000000, 0x20100000),  # Cortex-M default SRAM
    (0x10000000, 0x10100000),  # NXP/Nordic SRAM aliases
    (0x1FFF0000, 0x20000000),  # some STM32 boot SRAM
]


@dataclass
class ProbeAttempt:
    """One JLinkExe invocation and its parsed result."""
    interface: str               # "SWD" or "JTAG"
    speed_khz: int
    device: str
    purpose: str                 # "connect", "halt-read", "idcode-scan"
    success: bool
    dpidr: Optional[int] = None
    idcodes: List[int] = field(default_factory=list)
    halted: bool = False
    memory_reads: List[Dict[str, Any]] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    error: Optional[str] = None


def decode_dpidr(dpidr: int) -> Dict[str, Any]:
    """Decode an ARM SW-DP DPIDR register value.

    Layout (per ADIv5):
      [31:28] REVISION
      [27:20] PARTNO
      [19:17] reserved / MIN
      [16]    MIN
      [15:12] VERSION
      [11:1]  DESIGNER (JEP106): [11:8] continuation count, [7:1] identity
      [0]     RAO (always 1)
    """
    revision = (dpidr >> 28) & 0xF
    partno = (dpidr >> 20) & 0xFF
    version = (dpidr >> 12) & 0xF
    designer = (dpidr >> 1) & 0x7FF
    continuation = (designer >> 7) & 0xF
    identity = designer & 0x7F
    vendor = JEP106_VENDORS.get((continuation, identity), "Unknown")
    return {
        "raw": f"0x{dpidr:08X}",
        "revision": revision,
        "partno": f"0x{partno:02X}",
        "version": version,
        "designer_continuation": continuation,
        "designer_identity": f"0x{identity:02X}",
        "vendor": vendor,
    }


def decode_idcode(idcode: int) -> Dict[str, Any]:
    """Decode a JTAG IDCODE (IEEE 1149.1).

    Layout:
      [31:28] version
      [27:12] part number
      [11:1]  manufacturer (JEP106): [11:8] continuation, [7:1] identity
      [0]     RAO (always 1)
    """
    version = (idcode >> 28) & 0xF
    partno = (idcode >> 12) & 0xFFFF
    manufacturer = (idcode >> 1) & 0x7FF
    continuation = (manufacturer >> 7) & 0xF
    identity = manufacturer & 0x7F
    vendor = JEP106_VENDORS.get((continuation, identity), "Unknown")
    return {
        "raw": f"0x{idcode:08X}",
        "version": version,
        "partno": f"0x{partno:04X}",
        "manufacturer_continuation": continuation,
        "manufacturer_identity": f"0x{identity:02X}",
        "vendor": vendor,
    }


def find_jlink_binary() -> Optional[str]:
    """Locate the JLinkExe binary on PATH."""
    for name in ("JLinkExe", "JLinkExeCL", "jlinkexe"):
        path = shutil.which(name)
        if path:
            return path
    return None


# Regexes for parsing JLinkExe stdout.
RE_DPIDR = re.compile(r"DPIDR:\s*0x([0-9A-Fa-f]+)")
RE_DP_FOUND = re.compile(r"Found SW-DP with ID\s*0x([0-9A-Fa-f]+)", re.IGNORECASE)
RE_JTAG_IDCODE = re.compile(r"JTAG ID:\s*0x([0-9A-Fa-f]+)", re.IGNORECASE)
RE_IDCODE_LINE = re.compile(r"\bID(?:CODE)?\s*[:=]\s*0x([0-9A-Fa-f]+)", re.IGNORECASE)
RE_CANNOT_CONNECT = re.compile(r"Cannot connect to target|Could not connect|no target|not halted", re.IGNORECASE)
RE_HALTED = re.compile(r"PC =\s*0x[0-9A-Fa-f]+|Halted CPU|core halted|Reset and halted", re.IGNORECASE)
RE_MEM_LINE = re.compile(r"^([0-9A-Fa-f]{8})\s*=\s*((?:[0-9A-Fa-f]{8}\s*)+)", re.MULTILINE)


def parse_jlink_output(stdout: str) -> Dict[str, Any]:
    """Extract DPIDR / IDCODEs / halt state / memory reads from JLinkExe output."""
    parsed: Dict[str, Any] = {
        "dpidr": None,
        "idcodes": [],
        "halted": False,
        "memory": [],
        "cannot_connect": bool(RE_CANNOT_CONNECT.search(stdout)),
    }

    m = RE_DPIDR.search(stdout) or RE_DP_FOUND.search(stdout)
    if m:
        parsed["dpidr"] = int(m.group(1), 16)

    for m in RE_JTAG_IDCODE.finditer(stdout):
        parsed["idcodes"].append(int(m.group(1), 16))
    if not parsed["idcodes"]:
        for m in RE_IDCODE_LINE.finditer(stdout):
            val = int(m.group(1), 16)
            if val not in (0, 0xFFFFFFFF):
                parsed["idcodes"].append(val)

    if RE_HALTED.search(stdout):
        parsed["halted"] = True

    for m in RE_MEM_LINE.finditer(stdout):
        addr = int(m.group(1), 16)
        words = [int(w, 16) for w in m.group(2).split() if w]
        parsed["memory"].append({"address": f"0x{addr:08X}", "words": [f"0x{w:08X}" for w in words]})

    return parsed


def looks_like_vector_table(words: List[int]) -> bool:
    """Heuristic: a Cortex-M vector table starts with an initial SP (SRAM
    address) followed by a reset vector pointing into flash (LSB=1, Thumb).
    """
    if len(words) < 2:
        return False
    sp, reset = words[0], words[1]
    in_sram = any(lo <= sp < hi for lo, hi in SRAM_PLAUSIBLE_RANGES)
    thumb = (reset & 1) == 1
    return in_sram and thumb


class JLinkRunner:
    """Wraps JLinkExe invocations with timeout and script-file management."""

    def __init__(self, binary: str, timeout: float = 15.0, verbose: bool = False):
        self.binary = binary
        self.timeout = timeout
        self.verbose = verbose

    def run_script(
        self,
        script: str,
        interface: str,
        speed_khz: int,
        device: str,
    ) -> Tuple[str, str, Optional[str]]:
        """Run a JLinkExe command script. Returns (stdout, stderr, error)."""
        with tempfile.NamedTemporaryFile("w", suffix=".jlink", delete=False) as f:
            f.write(script)
            script_path = f.name

        args = [
            self.binary,
            "-NoGui", "1",
            "-ExitOnError", "1",
            "-AutoConnect", "1",
            "-If", interface,
            "-Speed", str(speed_khz),
            "-Device", device,
            "-CommanderScript", script_path,
        ]
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return proc.stdout, proc.stderr, None
        except subprocess.TimeoutExpired as e:
            return (e.stdout or "") if isinstance(e.stdout, str) else "", \
                   (e.stderr or "") if isinstance(e.stderr, str) else "", \
                   f"JLinkExe timed out after {self.timeout}s"
        except FileNotFoundError:
            return "", "", f"JLinkExe binary not found: {self.binary}"
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass


def script_connect_only() -> str:
    """Minimal script: connect, print device info, exit. Used to probe layer 1."""
    return "si 1\nconnect\nq\n"


def script_halt_and_read(flash_bases: List[int]) -> str:
    """Connect, halt, read CPUID + a handful of words at each candidate flash base."""
    lines = ["connect", "halt", "mem32 0xE000ED00 1"]
    for base in flash_bases:
        lines.append(f"mem32 0x{base:08X} 4")
    lines.append("q")
    return "\n".join(lines) + "\n"


def script_jtag_scan() -> str:
    """JTAG-only: auto-detect chain via JTAGConf, print IDCODEs."""
    return "JTAGConf -1 -1\nconnect\nq\n"


class JtagProbeTool(ToolInterface):
    """SWD/JTAG debug interface probe via SEGGER J-Link."""

    @property
    def name(self) -> str:
        return "jtagprobe"

    @property
    def description(self) -> str:
        return "Probe targets for exposed SWD/JTAG debug via SEGGER J-Link"

    def run(self, config: ToolConfig) -> ToolResult:
        start = time.time()
        custom = config.custom_args or {}

        interfaces: List[str] = custom.get("interfaces") or ["SWD", "JTAG"]
        speeds: List[int] = custom.get("speeds") or [4000, 1000, 100]
        per_attempt_timeout: float = float(custom.get("attempt_timeout", 15.0))
        device_override: Optional[str] = custom.get("device")
        skip_memory_test: bool = bool(custom.get("skip_memory", False))
        evidence_dir: Optional[str] = custom.get("evidence_dir")

        binary = custom.get("jlink_binary") or find_jlink_binary()
        if not binary:
            return ToolResult(
                success=False,
                data={},
                errors=["JLinkExe not found on PATH. Install SEGGER J-Link software."],
                metadata={"tool": self.name},
                execution_time=time.time() - start,
            )

        runner = JLinkRunner(binary, timeout=per_attempt_timeout, verbose=config.verbose)
        attempts: List[ProbeAttempt] = []

        # ---- Phase 1: connect sweep -----------------------------------------
        connect_success: Optional[ProbeAttempt] = None
        devices_to_try = [device_override] if device_override else GENERIC_DEVICES[:2]

        for iface in interfaces:
            for speed in speeds:
                for dev in devices_to_try:
                    stdout, stderr, err = runner.run_script(
                        script_connect_only(), iface, speed, dev
                    )
                    parsed = parse_jlink_output(stdout)
                    attempt = ProbeAttempt(
                        interface=iface,
                        speed_khz=speed,
                        device=dev,
                        purpose="connect",
                        success=parsed["dpidr"] is not None or bool(parsed["idcodes"]),
                        dpidr=parsed["dpidr"],
                        idcodes=parsed["idcodes"],
                        halted=parsed["halted"],
                        memory_reads=parsed["memory"],
                        raw_stdout=stdout,
                        raw_stderr=stderr,
                        error=err,
                    )
                    attempts.append(attempt)
                    if attempt.success and connect_success is None:
                        connect_success = attempt
                        break  # stop trying devices at this speed
                if connect_success:
                    break
            if connect_success:
                break

        # Optional JTAG chain scan if SWD failed but JTAG was attempted.
        if not connect_success and "JTAG" in interfaces:
            for speed in speeds:
                stdout, stderr, err = runner.run_script(
                    script_jtag_scan(), "JTAG", speed, devices_to_try[0]
                )
                parsed = parse_jlink_output(stdout)
                attempt = ProbeAttempt(
                    interface="JTAG",
                    speed_khz=speed,
                    device=devices_to_try[0],
                    purpose="idcode-scan",
                    success=bool(parsed["idcodes"]),
                    idcodes=parsed["idcodes"],
                    raw_stdout=stdout,
                    raw_stderr=stderr,
                    error=err,
                )
                attempts.append(attempt)
                if attempt.success:
                    connect_success = attempt
                    break

        # ---- Phase 2: identify ---------------------------------------------
        identification: Dict[str, Any] = {}
        if connect_success:
            if connect_success.dpidr is not None:
                identification["dp"] = decode_dpidr(connect_success.dpidr)
            if connect_success.idcodes:
                identification["jtag"] = [decode_idcode(i) for i in connect_success.idcodes]

        # JTAG IDCODE manufacturer == silicon vendor.
        # DPIDR designer == DP designer (almost always ARM, NOT the silicon vendor).
        # Prefer JTAG; fall back to a device-name hint if the user passed one;
        # otherwise mark vendor as Unknown and keep the DP designer separate.
        jtag_vendor = (
            identification["jtag"][0].get("vendor")
            if identification.get("jtag") else None
        )
        dp_designer = identification.get("dp", {}).get("vendor")
        vendor = jtag_vendor or "Unknown"
        if vendor == "Unknown" and device_override:
            for v in VENDOR_FLASH_BASES:
                if v.lower().split("/")[0][:4] in device_override.lower():
                    vendor = v
                    break

        # ---- Phase 3: halt + memory read ------------------------------------
        access: Dict[str, Any] = {
            "halted": False,
            "cpuid": None,
            "flash_reads": [],
            "vector_table_plausible": False,
        }
        halt_attempt: Optional[ProbeAttempt] = None
        if connect_success and not skip_memory_test:
            flash_bases = VENDOR_FLASH_BASES.get(vendor, DEFAULT_FLASH_BASES)
            stdout, stderr, err = runner.run_script(
                script_halt_and_read(flash_bases),
                connect_success.interface,
                connect_success.speed_khz,
                connect_success.device,
            )
            parsed = parse_jlink_output(stdout)
            halt_attempt = ProbeAttempt(
                interface=connect_success.interface,
                speed_khz=connect_success.speed_khz,
                device=connect_success.device,
                purpose="halt-read",
                success=parsed["halted"] or bool(parsed["memory"]),
                dpidr=parsed["dpidr"],
                halted=parsed["halted"],
                memory_reads=parsed["memory"],
                raw_stdout=stdout,
                raw_stderr=stderr,
                error=err,
            )
            attempts.append(halt_attempt)
            access["halted"] = parsed["halted"]

            for mread in parsed["memory"]:
                addr = int(mread["address"], 16)
                words = [int(w, 16) for w in mread["words"]]
                entry = {
                    "address": mread["address"],
                    "words": mread["words"],
                    "all_ones": all(w == 0xFFFFFFFF for w in words),
                    "all_zero": all(w == 0 for w in words),
                }
                if addr == 0xE000ED00:
                    access["cpuid"] = mread["words"][0] if mread["words"] else None
                else:
                    entry["vector_table_plausible"] = looks_like_vector_table(words)
                    if entry["vector_table_plausible"]:
                        access["vector_table_plausible"] = True
                    access["flash_reads"].append(entry)

        # ---- Phase 4: classify ----------------------------------------------
        if not connect_success:
            classification = "DEAD"
            classification_reason = "No DP/IDCODE response on any tested interface or speed."
        elif access["vector_table_plausible"] and access["halted"]:
            classification = "OPEN"
            classification_reason = "Connected, halted core, and read a plausible vector table."
        elif access["halted"] and access["flash_reads"]:
            # Halted but reads look suspicious (all-FF or all-zero).
            sus = all(r["all_ones"] or r["all_zero"] for r in access["flash_reads"])
            if sus:
                classification = "LOCKED"
                classification_reason = (
                    "DP responded and core halted, but flash reads returned "
                    "all-0xFF / all-0x00 (readout protection signature)."
                )
            else:
                classification = "OPEN"
                classification_reason = "Connected, halted, and read non-sentinel memory."
        elif connect_success.dpidr is not None or connect_success.idcodes:
            classification = "LOCKED"
            classification_reason = (
                "DP/IDCODE accessible but CPU halt or memory read failed. "
                "Typical of RDP / CRP / APPROTECT engaged."
            )
        else:
            classification = "DEAD"
            classification_reason = "Indeterminate response from JLinkExe."

        # Vendor-specific protection hint.
        protection_hint = None
        if classification == "LOCKED":
            protection_hint = {
                "STMicroelectronics": "STM32 RDP Level 1/2 (see RM, FLASH_OPTR bits 15:8).",
                "NXP": "LPC CRP1/CRP2 or Kinetis FSEC. Check vector 0x000002FC / FSEC byte.",
                "Nordic Semiconductor": "APPROTECT enabled in UICR. ERASEALL via CTRL-AP may recover.",
                "Texas Instruments": "MSP debug security or FlashSS lockout.",
                "Silicon Labs": "AAP lock / DEBUGLOCK page.",
                "Espressif": "ESP32 eFuse JTAG_DISABLE or secure boot.",
            }.get(vendor)

        # ---- Evidence capture -----------------------------------------------
        evidence_files: List[str] = []
        if evidence_dir:
            try:
                os.makedirs(evidence_dir, exist_ok=True)
                for i, att in enumerate(attempts):
                    fname = f"{i:02d}-{att.purpose}-{att.interface}-{att.speed_khz}khz.log"
                    fpath = os.path.join(evidence_dir, fname)
                    with open(fpath, "w") as f:
                        f.write(f"# JLinkExe attempt: {att.purpose}\n")
                        f.write(f"# Interface={att.interface} Speed={att.speed_khz}kHz Device={att.device}\n")
                        f.write(f"# Success={att.success} Error={att.error}\n")
                        f.write("\n--- STDOUT ---\n")
                        f.write(att.raw_stdout)
                        f.write("\n--- STDERR ---\n")
                        f.write(att.raw_stderr)
                    evidence_files.append(fpath)
            except OSError as e:
                pass  # non-fatal

        data = {
            "classification": classification,
            "classification_reason": classification_reason,
            "vendor": vendor,
            "dp_designer": dp_designer,
            "identification": identification,
            "access": access,
            "protection_hint": protection_hint,
            "attempts": [
                {
                    "interface": a.interface,
                    "speed_khz": a.speed_khz,
                    "device": a.device,
                    "purpose": a.purpose,
                    "success": a.success,
                    "dpidr": f"0x{a.dpidr:08X}" if a.dpidr is not None else None,
                    "idcodes": [f"0x{i:08X}" for i in a.idcodes],
                    "halted": a.halted,
                    "error": a.error,
                }
                for a in attempts
            ],
            "evidence_files": evidence_files,
        }

        return ToolResult(
            success=True,
            data=data,
            errors=[],
            metadata={
                "tool": self.name,
                "jlink_binary": binary,
                "interfaces_tried": interfaces,
                "speeds_tried": speeds,
                "attempts": len(attempts),
            },
            execution_time=time.time() - start,
        )
