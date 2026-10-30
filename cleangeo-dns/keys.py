"""Key and certificate management for the CleanGEO DoH server.

Rules this module enforces, rather than documents:

* Private keys are read from files that must not be readable by other users.
  A key with mode 0644 is refused, not warned about.
* Nothing here generates keys into the repository. `keygen` writes to the
  path you give, which is expected to be outside version control.
* Expiry is checked, and the days-remaining number is reported so a renewal can
  be scheduled instead of discovered.
* An ACME/Let's Encrypt layout is supported (`fullchain.pem` + `privkey.pem`),
  because that is the realistic production path for a public DNS hostname.

The pin file is separate on purpose: the client's trust anchor for the
experimental control channel is a 32-byte Ed25519 public key, not a DNS name.
"""
from __future__ import annotations

import datetime
import hashlib
import os
import ssl
import stat
import subprocess
import sys
from dataclasses import dataclass

MIN_KEY_MODE = 0o600
WARN_DAYS = 21


class KeyError_(Exception):
    pass


def check_private_file(path: str, *, label: str = "key") -> None:
    try:
        info = os.stat(path)
    except FileNotFoundError:
        raise KeyError_("%s not found: %s" % (label, path))
    if not stat.S_ISREG(info.st_mode):
        raise KeyError_("%s is not a regular file: %s" % (label, path))
    mode = info.st_mode & 0o777
    if mode & 0o077:
        raise KeyError_(
            "%s is accessible to other users (mode %04o); run: chmod 600 %s"
            % (label, mode, path))


@dataclass
class CertificateInfo:
    subject: str
    not_before: str
    not_after: str
    days_left: int
    fingerprint_sha256: str
    sans: list[str]

    def to_dict(self) -> dict:
        return {"subject": self.subject, "notBefore": self.not_before,
                "notAfter": self.not_after, "daysRemaining": self.days_left,
                "sha256": self.fingerprint_sha256, "sans": self.sans}

    @property
    def fresh_enough(self) -> bool:
        return self.days_left > WARN_DAYS


def inspect_certificate(path: str) -> CertificateInfo:
    """Parse a PEM certificate, including its expiry."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    with open(path, "rb") as handle:
        pem = handle.read()
    certificates = x509.load_pem_x509_certificates(pem)
    leaf = certificates[0]
    try:
        sans = list(leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = []
    expiry = leaf.not_valid_after_utc
    now = datetime.datetime.now(datetime.timezone.utc)
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    return CertificateInfo(
        subject=leaf.subject.rfc4514_string(),
        not_before=leaf.not_valid_before_utc.isoformat(),
        not_after=expiry.isoformat(),
        days_left=(expiry - now).days,
        fingerprint_sha256=":".join(fingerprint[i:i + 2]
                                    for i in range(0, len(fingerprint), 2)),
        sans=sans)


def chain_files(directory: str) -> tuple[str, str]:
    """Resolve an ACME-style directory to (certificate chain, private key)."""
    directory = os.path.expanduser(directory)
    if not os.path.isdir(directory):
        raise KeyError_("not a directory: %s" % directory)

    key = os.path.join(directory, "privkey.pem")
    if not os.path.isfile(key):
        raise KeyError_("no privkey.pem in %s" % directory)

    preferred = os.path.join(directory, "fullchain.pem")
    if os.path.isfile(preferred):
        return preferred, key

    candidates = sorted(name for name in os.listdir(directory)
                        if name.endswith(".pem") and "privkey" not in name)
    if not candidates:
        raise KeyError_("no certificate PEM in %s" % directory)
    return os.path.join(directory, candidates[0]), key


def check_pair(certfile: str, keyfile: str) -> CertificateInfo:
    """Validate a certificate/key pair and report its expiry.

    The match is proved by comparing the public key in the certificate against
    the public key derived from the private key. That works on any build, unlike
    `ssl.SSLContext.load_cert_chain`, which needs a TLS implementation to be
    present.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    check_private_file(keyfile, label="private key")
    info = inspect_certificate(certfile)

    with open(keyfile, "rb") as handle:
        private_key = serialization.load_pem_private_key(handle.read(),
                                                         password=None)
    with open(certfile, "rb") as handle:
        certificate = x509.load_pem_x509_certificates(handle.read())[0]

    cert_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    key_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_public != key_public:
        raise KeyError_("certificate and key do not form a valid pair")
    return info


@dataclass
class PinFile:
    """The client trust anchor for the experimental control channel."""
    public_key_hex: str
    created: str

    @property
    def public_key(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)

    def to_dict(self) -> dict:
        return {"cstpServerKey": self.public_key_hex, "created": self.created,
                "algorithm": "Ed25519",
                "note": "pin this in the client; it is not a TLS certificate"}


def load_pin(path: str) -> PinFile:
    import json
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    key_hex = data.get("cstpServerKey", "")
    if len(key_hex) != 64:
        raise KeyError_("pin file does not hold a 32-byte Ed25519 key")
    bytes.fromhex(key_hex)  # raises on non-hex
    return PinFile(key_hex, data.get("created", ""))


def write_pin(path: str, public_key: bytes) -> PinFile:
    import json
    if len(public_key) != 32:
        raise KeyError_("Ed25519 public keys are 32 bytes")
    pin = PinFile(public_key.hex(),
                  datetime.datetime.now(datetime.timezone.utc).isoformat())
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(pin.to_dict(), handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o644)  # a public key is not a secret
    return pin


def keygen(directory: str, hostname: str, *, days: int = 90) -> tuple[str, str]:
    """Dev/self-signed helper. Production uses ACME, not this.

    Written against `cryptography` rather than shelling out to openssl, so it
    works on hosts without the openssl binary and cannot silently depend on a
    CLI's flags changing between versions.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    os.makedirs(directory, mode=0o700, exist_ok=True)
    cert_path = os.path.join(directory, "cert.pem")
    key_path = os.path.join(directory, "key.pem")

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                       critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .sign(key, hashes.SHA256()))

    with open(key_path, "wb") as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with open(cert_path, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    os.chmod(key_path, MIN_KEY_MODE)
    os.chmod(cert_path, 0o644)
    return cert_path, key_path


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "help"
    if command == "inspect" and len(sys.argv) == 3:
        print(inspect_certificate(sys.argv[2]).to_dict())
    elif command == "keygen" and len(sys.argv) >= 4:
        print(keygen(sys.argv[2], sys.argv[3]))
    elif command == "pin" and len(sys.argv) == 3:
        print(load_pin(sys.argv[2]).to_dict())
    else:
        print("usage: keys.py inspect <cert.pem>\n"
              "       keys.py keygen <dir> <hostname>\n"
              "       keys.py pin <pin.json>")
