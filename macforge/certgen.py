"""Certificate generation for lab EAP-TLS testing.

Uses the Python `cryptography` library to generate self-signed CAs,
client certificates, and CSRs without requiring external tools.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("MACFORGE_DATA_DIR", "/app/data"))
CERTS_DIR = DATA_DIR / "certs"

_DEFAULT_KEY_SIZE = 2048
_DEFAULT_DAYS = 3650


def _ensure_certs_dir() -> None:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_csr(path: Path, csr: x509.CertificateSigningRequest) -> None:
    path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))


def _cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex(":")


def generate_lab_ca(
    cn: str = "MACforge Lab CA",
    org: str = "MACforge Lab",
    days: int = _DEFAULT_DAYS,
    key_size: int = _DEFAULT_KEY_SIZE,
) -> dict:
    """Generate a self-signed CA cert and key for lab use.

    Saves lab-ca.pem and lab-ca.key to CERTS_DIR.
    Returns metadata dict.
    """
    _ensure_certs_dir()

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lab"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = CERTS_DIR / "lab-ca.pem"
    key_path = CERTS_DIR / "lab-ca.key"
    _write_cert(cert_path, cert)
    _write_key(key_path, key)

    logger.info("Generated Lab CA: %s", cn)

    return {
        "cert_file": "lab-ca.pem",
        "key_file": "lab-ca.key",
        "cn": cn,
        "org": org,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint": _cert_fingerprint(cert),
    }


def generate_client_cert(
    cn: str,
    san_list: Optional[list[str]] = None,
    ca_cert_file: str = "lab-ca.pem",
    ca_key_file: str = "lab-ca.key",
    days: int = _DEFAULT_DAYS,
    key_size: int = _DEFAULT_KEY_SIZE,
) -> dict:
    """Generate a client certificate signed by a CA.

    The cert includes extendedKeyUsage=clientAuth for EAP-TLS.
    Returns metadata dict.
    """
    _ensure_certs_dir()

    ca_cert_path = CERTS_DIR / ca_cert_file
    ca_key_path = CERTS_DIR / ca_key_file
    if not ca_cert_path.exists() or not ca_key_path.exists():
        raise FileNotFoundError(
            f"CA files not found: {ca_cert_file}, {ca_key_file}. "
            "Generate a Lab CA first."
        )

    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(
        ca_key_path.read_bytes(), password=None
    )

    client_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lab"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MACforge Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    if san_list:
        names = [x509.RFC822Name(s) for s in san_list]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )

    cert = builder.sign(ca_key, hashes.SHA256())

    safe_name = cn.replace("@", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
    cert_file = f"{safe_name}.pem"
    key_file = f"{safe_name}.key"

    _write_cert(CERTS_DIR / cert_file, cert)
    _write_key(CERTS_DIR / key_file, client_key)

    logger.info("Generated client cert: %s (signed by %s)", cn, ca_cert_file)

    return {
        "cert_file": cert_file,
        "key_file": key_file,
        "cn": cn,
        "issuer_cn": ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint": _cert_fingerprint(cert),
    }


def generate_csr(
    cn: str,
    san_list: Optional[list[str]] = None,
    key_size: int = _DEFAULT_KEY_SIZE,
) -> dict:
    """Generate a private key and CSR for external signing.

    Returns metadata dict with csr_file and key_file names.
    """
    _ensure_certs_dir()

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lab"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MACforge"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    builder = builder.add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=False,
    )

    if san_list:
        names = [x509.RFC822Name(s) for s in san_list]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        )

    csr = builder.sign(key, hashes.SHA256())

    safe_name = cn.replace("@", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
    csr_file = f"{safe_name}.csr"
    key_file = f"{safe_name}.key"

    _write_csr(CERTS_DIR / csr_file, csr)
    _write_key(CERTS_DIR / key_file, key)

    logger.info("Generated CSR: %s", cn)

    return {
        "csr_file": csr_file,
        "key_file": key_file,
        "cn": cn,
    }


def parse_cert_info(filename: str) -> dict:
    """Parse a PEM certificate and return its metadata."""
    _ensure_certs_dir()
    path = CERTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Certificate not found: {filename}")

    content = path.read_bytes()

    if b"-----BEGIN CERTIFICATE-----" not in content:
        return {
            "filename": filename,
            "type": "not_a_certificate",
            "detail": "File does not contain a PEM certificate",
        }

    try:
        cert = x509.load_pem_x509_certificate(content)
    except Exception as exc:
        return {
            "filename": filename,
            "type": "parse_error",
            "detail": str(exc),
        }

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer_cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bc.value.ca
    except x509.ExtensionNotFound:
        pass

    return {
        "filename": filename,
        "type": "ca_certificate" if is_ca else "client_certificate",
        "cn": cn_attrs[0].value if cn_attrs else "",
        "issuer_cn": issuer_cn_attrs[0].value if issuer_cn_attrs else "",
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": format(cert.serial_number, "x"),
        "key_size": cert.public_key().key_size,
        "fingerprint": _cert_fingerprint(cert),
        "is_ca": is_ca,
        "is_self_signed": cert.subject == cert.issuer,
    }


def get_lab_ca_info() -> Optional[dict]:
    """Return Lab CA metadata if it exists, else None."""
    ca_path = CERTS_DIR / "lab-ca.pem"
    if not ca_path.exists():
        return None
    try:
        return parse_cert_info("lab-ca.pem")
    except Exception:
        return None
