"""Per-run certificate authority for reading HTTPS traffic in the sandbox.

The Wiretap proxy normally relays an HTTPS tunnel blind, so it can see which
host a script connected to but not what it sent, and a stolen secret leaving
over HTTPS (how real malware sends it) goes unproven. With interception on,
the proxy ends the sandbox's TLS itself using a certificate for the
requested host that is signed by a CA created for this one run, reads the
request, then re-encrypts it to the real server, verifying that server's
certificate normally.

The CA's private key lives only inside the Wiretap container. The sandbox
gets the CA *certificate* (so its tools trust the proxy) and nothing else,
and both are discarded when the run ends.

Needs the `cryptography` package, which the Wiretap image installs; the host
never loads this module. Everything here fails closed to "no interception":
the caller falls back to the blind relay.
"""
from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_VALIDITY = datetime.timedelta(days=1)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class CertificateAuthority:
    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MalwHunter sandbox CA (single run)")])
        now = _now()
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + _VALIDITY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            # Python 3.13's default verification is strict: it wants key identifiers on every certificate
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )
        self._leaf_key = ec.generate_private_key(ec.SECP256R1())  # one key for every host; only the cert differs
        self._contexts: dict[str, ssl.SSLContext] = {}

    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def write_certificate(self, path: Path) -> None:
        path.write_bytes(self.certificate_pem())

    def server_context(self, host: str) -> ssl.SSLContext:
        """A TLS server context presenting a certificate for `host`."""
        if host in self._contexts:
            return self._contexts[host]

        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = _now()
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:60] or "sandbox")]))
            .issuer_name(self.certificate.subject)
            .public_key(self._leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + _VALIDITY)
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        chain = leaf.public_bytes(serialization.Encoding.PEM) + self.certificate_pem()
        key = self._leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

        # ssl can only load a certificate from a file; keep it on disk for
        # exactly as long as that takes
        fd, cert_path = tempfile.mkstemp(suffix=".pem")
        fd_key, key_path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(chain)
            with os.fdopen(fd_key, "wb") as fh:
                fh.write(key)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert_path, key_path)
            ctx.set_alpn_protocols(["http/1.1"])  # never agree to HTTP/2: the proxy reads HTTP/1.1
        finally:
            for path in (cert_path, key_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        self._contexts[host] = ctx
        return ctx


def upstream_context() -> ssl.SSLContext:
    """How the proxy talks to the real server: ordinary, verified TLS."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx
