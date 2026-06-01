#!/usr/bin/env python3
"""CLI entry point for jtagprobe — SWD/JTAG debug interface probing via J-Link."""

import argparse
import json

from colorama import init, Fore

from .core.interfaces import OutputFormatter, ToolConfig, ToolResult
from .core.jtagprobe_core import JtagProbeTool


class JtagProbeOutputFormatter(OutputFormatter):
    """Renders jtagprobe results."""

    def _format_text(self, result: ToolResult) -> str:
        if not result.success:
            return Fore.RED + "FAILED: " + "; ".join(result.errors) + Fore.RESET

        data = result.data
        lines: list[str] = []

        cls = data.get("classification", "UNKNOWN")
        color = {
            "OPEN": Fore.RED,
            "LOCKED": Fore.YELLOW,
            "DEAD": Fore.GREEN,
        }.get(cls, Fore.WHITE)
        lines.append(f"{color}CLASSIFICATION: {cls}{Fore.RESET}")
        lines.append(Fore.CYAN + data.get("classification_reason", "") + Fore.RESET)
        lines.append("")

        vendor = data.get("vendor", "Unknown")
        dp_designer = data.get("dp_designer")
        lines.append(Fore.BLUE + f"Silicon vendor: {vendor}" + Fore.RESET)
        if dp_designer:
            lines.append(Fore.BLUE + f"DP designer: {dp_designer} (DP designer, not chip vendor)" + Fore.RESET)

        ident = data.get("identification", {})
        if ident.get("dp"):
            dp = ident["dp"]
            lines.append(
                f"  SW-DP DPIDR={dp['raw']} partno={dp['partno']} "
                f"version={dp['version']} designer_identity={dp['designer_identity']}"
            )
        for idc in ident.get("jtag", []) or []:
            lines.append(
                f"  JTAG IDCODE={idc['raw']} partno={idc['partno']} "
                f"manufacturer_identity={idc['manufacturer_identity']}"
            )

        access = data.get("access", {})
        if access:
            lines.append("")
            lines.append(Fore.BLUE + "Access test:" + Fore.RESET)
            lines.append(f"  Halted: {access.get('halted')}")
            if access.get("cpuid"):
                lines.append(f"  CPUID @ 0xE000ED00 = {access['cpuid']}")
            for fr in access.get("flash_reads", []):
                tag = ""
                if fr.get("all_ones"):
                    tag = Fore.YELLOW + " [all-0xFF, possible RDP]" + Fore.RESET
                elif fr.get("all_zero"):
                    tag = Fore.YELLOW + " [all-0x00]" + Fore.RESET
                elif fr.get("vector_table_plausible"):
                    tag = Fore.GREEN + " [plausible vector table]" + Fore.RESET
                lines.append(f"  {fr['address']}: {' '.join(fr['words'])}{tag}")

        if data.get("protection_hint"):
            lines.append("")
            lines.append(Fore.YELLOW + "Protection hint: " + Fore.RESET + data["protection_hint"])

        lines.append("")
        lines.append(Fore.BLUE + f"Probe attempts: {len(data.get('attempts', []))}" + Fore.RESET)
        for a in data.get("attempts", []):
            status = (Fore.GREEN + "OK" + Fore.RESET) if a["success"] else (Fore.RED + "FAIL" + Fore.RESET)
            extra = []
            if a.get("dpidr"):
                extra.append(f"DPIDR={a['dpidr']}")
            if a.get("idcodes"):
                extra.append(f"IDCODE={a['idcodes'][0]}")
            if a.get("error"):
                extra.append(f"err={a['error']}")
            extra_str = " ".join(extra)
            lines.append(
                f"  [{status}] {a['purpose']:<12} {a['interface']:<4} "
                f"{a['speed_khz']:>5}kHz device={a['device']} {extra_str}"
            )

        if data.get("evidence_files"):
            lines.append("")
            lines.append(Fore.BLUE + "Evidence saved:" + Fore.RESET)
            for f in data["evidence_files"]:
                lines.append(f"  {f}")

        return "\n".join(lines)

    def _format_json(self, result: ToolResult) -> str:
        return json.dumps(result.data, indent=2, default=str)

    def _format_quiet(self, result: ToolResult) -> str:
        if not result.success:
            return ""
        cls = result.data.get("classification", "UNKNOWN")
        vendor = result.data.get("vendor", "Unknown")
        return f"{cls} {vendor}"


def _parse_speeds(value: str) -> list:
    return [int(s.strip()) for s in value.split(",") if s.strip()]


def _parse_interfaces(value: str) -> list:
    out = []
    for iface in value.split(","):
        iface = iface.strip().upper()
        if iface in ("SWD", "JTAG"):
            out.append(iface)
    if not out:
        raise argparse.ArgumentTypeError("interfaces must be SWD, JTAG, or both (comma-separated)")
    return out


def jtagprobe() -> int:
    parser = argparse.ArgumentParser(
        prog="jtagprobe",
        description="Probe a target for exposed SWD/JTAG debug via SEGGER J-Link.",
    )
    parser.add_argument(
        "--interfaces",
        type=_parse_interfaces,
        default=["SWD", "JTAG"],
        help="Interfaces to try, comma-separated (default: SWD,JTAG)",
    )
    parser.add_argument(
        "--speeds",
        type=_parse_speeds,
        default=[4000, 1000, 100],
        help="Clock speeds in kHz to sweep, comma-separated (default: 4000,1000,100)",
    )
    parser.add_argument(
        "--device",
        help="Specific J-Link device name (e.g. STM32F407VG). Default: Cortex-M0/M3.",
    )
    parser.add_argument(
        "--attempt-timeout",
        type=float,
        default=15.0,
        help="Timeout per JLinkExe invocation in seconds (default: 15)",
    )
    parser.add_argument(
        "--skip-memory",
        action="store_true",
        help="Skip the halt+memory-read access test (phase 1 only)",
    )
    parser.add_argument(
        "--evidence-dir",
        help="Directory to write per-attempt JLinkExe stdout/stderr logs",
    )
    parser.add_argument(
        "--jlink-binary",
        help="Path to JLinkExe binary (default: auto-detect from PATH)",
    )
    parser.add_argument("--format", choices=["text", "json", "quiet"], default="text")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    init()

    config = ToolConfig(
        input_paths=[],
        output_format=args.format,
        verbose=args.verbose,
        custom_args={
            "interfaces": args.interfaces,
            "speeds": args.speeds,
            "device": args.device,
            "attempt_timeout": args.attempt_timeout,
            "skip_memory": args.skip_memory,
            "evidence_dir": args.evidence_dir,
            "jlink_binary": args.jlink_binary,
        },
    )

    tool = JtagProbeTool()
    result = tool.run(config)

    formatter = JtagProbeOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    if not result.success:
        return 1
    return 0 if result.data.get("classification") != "DEAD" else 2
