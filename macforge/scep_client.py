"""SCEP/EST enrollment client for enterprise PKI integration.

Supports certificate enrollment via:
- AD CS / NDES (SCEP protocol using sscep or step CLI)
- step-ca sidecar (using step CLI)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
CERTS_DIR = DATA_DIR / "certs"


def _ensure_certs_dir() -> None:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)


def _find_tool(name: str) -> Optional[str]:
    return shutil.which(name)


async def _run_cmd(cmd: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return -1, "", "Command timed out"
    return proc.returncode, stdout.decode(), stderr.decode()


async def enroll_via_step_ca(
    ca_url: str,
    cn: str,
    provisioner: str = "macforge",
    token: Optional[str] = None,
    ca_fingerprint: Optional[str] = None,
) -> dict:
    """Enroll a client certificate via step-ca using the step CLI.

    Requires the `step` CLI tool to be installed.
    """
    _ensure_certs_dir()
    step_bin = _find_tool("step")
    if not step_bin:
        return {
            "status": "error",
            "message": "step CLI not found. Install smallstep step-cli to use step-ca enrollment.",
        }

    safe_name = cn.replace("@", "_").replace(".", "_").replace(" ", "_")
    cert_file = CERTS_DIR / f"{safe_name}.pem"
    key_file = CERTS_DIR / f"{safe_name}.key"

    cmd = [
        step_bin, "ca", "certificate",
        cn,
        str(cert_file),
        str(key_file),
        "--ca-url", ca_url,
        "--provisioner", provisioner,
        "--not-after", "8760h",
        "--force",
    ]

    if ca_fingerprint:
        cmd.extend(["--root", "/dev/null", "--fingerprint", ca_fingerprint])
    else:
        cmd.append("--insecure")

    if token:
        cmd.extend(["--token", token])

    rc, stdout, stderr = await _run_cmd(cmd, timeout=30.0)

    if rc != 0:
        return {
            "status": "error",
            "message": f"step-ca enrollment failed (exit {rc})",
            "detail": stderr[:1000],
        }

    logger.info("Enrolled via step-ca: %s", cn)
    return {
        "status": "ok",
        "cert_file": f"{safe_name}.pem",
        "key_file": f"{safe_name}.key",
        "cn": cn,
        "message": f"Certificate enrolled from {ca_url}",
    }


async def enroll_via_scep(
    ndes_url: str,
    challenge: str,
    cn: str,
    san: Optional[str] = None,
) -> dict:
    """Enroll a client certificate via SCEP (AD CS / NDES).

    Tries sscep first, falls back to step CLI with SCEP provisioner.
    The NDES URL should be the base URL, e.g.:
      http://ndes-server/certsrv/mscep/mscep.dll
    """
    _ensure_certs_dir()

    sscep_bin = _find_tool("sscep")
    step_bin = _find_tool("step")
    openssl_bin = _find_tool("openssl")

    safe_name = cn.replace("@", "_").replace(".", "_").replace(" ", "_")

    if sscep_bin and openssl_bin:
        return await _enroll_sscep(
            sscep_bin, openssl_bin, ndes_url, challenge, cn, safe_name, san=san
        )

    if step_bin:
        return {
            "status": "error",
            "message": (
                "Direct SCEP enrollment requires sscep and openssl. "
                "Install sscep or use the step-ca sidecar with a SCEP provisioner."
            ),
        }

    return {
        "status": "error",
        "message": (
            "No SCEP client tools found. Install sscep + openssl, "
            "or use the step-ca sidecar."
        ),
    }


async def _enroll_sscep(
    sscep_bin: str,
    openssl_bin: str,
    ndes_url: str,
    challenge: str,
    cn: str,
    safe_name: str,
    san: Optional[str] = None,
) -> dict:
    """Perform SCEP enrollment using sscep."""
    key_file = CERTS_DIR / f"{safe_name}.key"
    csr_file = CERTS_DIR / f"{safe_name}.csr"
    cert_file = CERTS_DIR / f"{safe_name}.pem"
    ca_file = CERTS_DIR / f"scep-ca-{safe_name}.pem"

    openssl_cmd = [
        openssl_bin, "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_file),
        "-out", str(csr_file),
        "-subj", f"/CN={cn}",
    ]
    if san:
        san_parts = [s.strip() for s in san.split(",") if s.strip()]
        openssl_cmd.extend(["-addext", f"subjectAltName={','.join(san_parts)}"])
    rc, _, stderr = await _run_cmd(openssl_cmd)
    if rc != 0:
        return {"status": "error", "message": f"Key/CSR generation failed: {stderr[:500]}"}

    rc, stdout, stderr = await _run_cmd([
        sscep_bin, "getca",
        "-u", ndes_url,
        "-c", str(ca_file),
    ])
    if rc != 0:
        return {"status": "error", "message": f"SCEP GetCACert failed: {stderr[:500]}"}

    # sscep getca writes cafile.0 (and .1, .2 for chains) rather than cafile
    # directly on many NDES setups.  Resolve the actual CA cert path.
    actual_ca_file = ca_file
    if not ca_file.exists():
        dotted = Path(str(ca_file) + ".0")
        if dotted.exists():
            actual_ca_file = dotted
        else:
            return {"status": "error", "message": "SCEP GetCACert succeeded but CA file not found (tried .0 suffix)"}

    rc, stdout, stderr = await _run_cmd([
        sscep_bin, "enroll",
        "-u", ndes_url,
        "-c", str(actual_ca_file),
        "-k", str(key_file),
        "-r", str(csr_file),
        "-l", str(cert_file),
        "-p", challenge,
        "-S", "sha256",
        "-n", "3",
        "-T", "5",
        "-t", "10",
    ], timeout=120.0)

    csr_file.unlink(missing_ok=True)

    if rc != 0:
        return {"status": "error", "message": f"SCEP enrollment failed: {stderr[:500]}"}

    # sscep enroll may also write certfile.0 instead of certfile
    if not cert_file.exists():
        dotted = Path(str(cert_file) + ".0")
        if dotted.exists():
            dotted.rename(cert_file)
        else:
            return {"status": "error", "message": "SCEP enrollment completed but cert file not found (tried .0 suffix)"}

    logger.info("SCEP enrollment succeeded: %s from %s", cn, ndes_url)
    return {
        "status": "ok",
        "cert_file": f"{safe_name}.pem",
        "key_file": f"{safe_name}.key",
        "ca_file": f"scep-ca-{safe_name}.pem",
        "cn": cn,
        "message": f"Certificate enrolled via SCEP from {ndes_url}",
    }


def get_enrollment_capabilities() -> dict:
    """Report which enrollment tools are available."""
    return {
        "sscep": _find_tool("sscep") is not None,
        "step_cli": _find_tool("step") is not None,
        "openssl": _find_tool("openssl") is not None,
    }
