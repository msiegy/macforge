"""CLI entry point for MACforge."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path

import uvicorn


def _list_physical_interfaces() -> list[str]:
    """Return all non-loopback interfaces sorted by name."""
    try:
        return sorted(
            p.name for p in Path("/sys/class/net").iterdir()
            if p.name != "lo"
        )
    except Exception:
        return []


def _default_route_iface() -> str | None:
    """Return the interface that carries the default route, or None."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=3
        )
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def _detect_mgmt_interface() -> str:
    """Return the management (web UI) interface.

    Resolution order:
    1. MACFORGE_IFACE env var
    2. Interface carrying the default route (has gateway → likely management)
    3. First non-loopback in /sys/class/net
    4. Hard fallback: eth0
    """
    env = os.environ.get("MACFORGE_IFACE", "").strip()
    if env:
        return env
    iface = _default_route_iface()
    if iface:
        return iface
    ifaces = _list_physical_interfaces()
    if ifaces:
        return ifaces[0]
    return "eth0"


def _detect_data_interface(mgmt_iface: str) -> str:
    """Return the NAD/data (switch-facing) interface.

    Resolution order:
    1. MACFORGE_DATA_IFACE env var
    2. If exactly one non-loopback interface exists besides mgmt → use it
    3. Fall back to mgmt_iface (single-NIC deployments)
    """
    env = os.environ.get("MACFORGE_DATA_IFACE", "").strip()
    if env:
        return env
    others = [i for i in _list_physical_interfaces() if i != mgmt_iface]
    if len(others) == 1:
        return others[0]
    # Multiple candidates or none — default to same as mgmt (single-NIC)
    return mgmt_iface

from macforge.orchestrator import Orchestrator
from macforge.dot1x import check_wpa_supplicant_version
from macforge.profiles import compute_seed, load_profiles, remap_profile_macs
from macforge.web import app, set_orchestrator


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    _mgmt = _detect_mgmt_interface()
    _data = _detect_data_interface(_mgmt)
    parser = argparse.ArgumentParser(
        prog="macforge",
        description="MACforge - MAC Authentication Bypass Device Emulator",
    )
    parser.add_argument(
        "--mode",
        choices=["web", "cli"],
        default="web",
        help="Run mode: 'web' starts the dashboard, 'cli' runs headless (default: web)",
    )
    parser.add_argument(
        "--interface", "-i",
        default=_mgmt,
        help="Management interface — web UI binds here (default: auto-detected or MACFORGE_IFACE)",
    )
    parser.add_argument(
        "--data-interface", "-d",
        default=_data,
        help=(
            "NAD/data interface — emulated device packets are sent here "
            "(default: auto-detected or MACFORGE_DATA_IFACE; falls back to --interface)"
        ),
    )
    parser.add_argument(
        "--profiles-dir", "-p",
        default=None,
        help="Path to device profiles directory (default: built-in profiles)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Web UI port (default: 8080)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Web UI bind address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--start-all",
        action="store_true",
        help="CLI mode: connect all devices immediately on startup",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


async def run_cli(orch: Orchestrator, start_all: bool) -> None:
    """Run in headless CLI mode."""
    # Pre-flight: log wpa_supplicant version and TEAP support status
    await check_wpa_supplicant_version()

    if start_all:
        logging.info("Connecting all devices...")
        await orch.connect_all()

    logging.info("Running in CLI mode. Press Ctrl+C to stop.")
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        logging.info("Shutting down -- disconnecting all devices...")
        await orch.disconnect_all()


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    setup_logging(args.verbose)

    logger = logging.getLogger("macforge")
    logger.info("MACforge starting up")
    mgmt = args.interface
    data = args.data_interface
    same = mgmt == data
    if same:
        logger.info("Network interface: %s (management + data, single-NIC mode)", mgmt)
    else:
        logger.info("Management interface : %s  (web UI, keepalive traffic)", mgmt)
        logger.info("Data/NAD interface   : %s  (EAP/MAB/DHCP emulated device traffic)", data)

    profiles = load_profiles(args.profiles_dir)
    if not profiles:
        logger.error("No device profiles found. Check --profiles-dir.")
        sys.exit(1)

    seed = compute_seed(data)
    remap_profile_macs(profiles, seed)

    logger.info("Loaded %d device profile(s)", len(profiles))
    for p in profiles:
        logger.info("  %s [%s] %s", p.name, p.mac, p.personality.category)

    orch = Orchestrator(profiles, data, seed=seed, mgmt_interface=mgmt)

    if args.mode == "web":
        set_orchestrator(orch)
        logger.info("Starting web UI on %s:%d", args.host, args.port)
        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info",
        )
    else:
        asyncio.run(run_cli(orch, args.start_all))


if __name__ == "__main__":
    main()
