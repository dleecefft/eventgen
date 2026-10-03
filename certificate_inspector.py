"""TLS certificate-chain inspection for approved HTTPS targets."""

from __future__ import annotations

import ipaddress
import select
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from OpenSSL import SSL

from event_generator_cli import build_ssl_context, normalize_url


@dataclass(frozen=True)
class CertificateDetails:
    position: int
    role: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before_utc: str
    not_valid_after_utc: str
    sha256_fingerprint: str
    signature_hash: str
    public_key_type: str
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    is_ca: bool | None
    self_issued: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CertificateChainResult:
    url: str
    hostname: str
    port: int
    tls_verified: bool
    tls_version: str
    cipher: str
    certificates: tuple[CertificateDetails, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "hostname": self.hostname,
            "port": self.port,
            "tls_verified": self.tls_verified,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "certificates": [certificate.to_dict() for certificate in self.certificates],
        }


def _certificate_details(
    certificate: x509.Certificate,
    position: int,
) -> CertificateDetails:
    try:
        alternative_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        dns_names = tuple(alternative_names.get_values_for_type(x509.DNSName))
        ip_addresses = tuple(
            str(address) for address in alternative_names.get_values_for_type(x509.IPAddress)
        )
    except x509.ExtensionNotFound:
        dns_names = ()
        ip_addresses = ()

    try:
        is_ca: bool | None = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.ca
    except x509.ExtensionNotFound:
        is_ca = None

    signature_hash = (
        certificate.signature_hash_algorithm.name
        if certificate.signature_hash_algorithm is not None
        else "unknown"
    )
    fingerprint = certificate.fingerprint(hashes.SHA256()).hex(":").upper()
    return CertificateDetails(
        position=position,
        role="leaf" if position == 0 else "intermediate-or-root",
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=f"{certificate.serial_number:X}",
        not_valid_before_utc=certificate.not_valid_before_utc.isoformat(),
        not_valid_after_utc=certificate.not_valid_after_utc.isoformat(),
        sha256_fingerprint=fingerprint,
        signature_hash=signature_hash,
        public_key_type=type(certificate.public_key()).__name__,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
        is_ca=is_ca,
        self_issued=certificate.subject == certificate.issuer,
    )


def _verified_handshake(hostname: str, port: int, timeout: float) -> tuple[str, str]:
    context = build_ssl_context(True)
    with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            cipher = tls_socket.cipher()
            return tls_socket.version() or "unknown", cipher[0] if cipher else "unknown"


def _presented_chain(
    hostname: str,
    port: int,
    timeout: float,
) -> tuple[str, str, tuple[x509.Certificate, ...]]:
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *_arguments: True)

    raw_socket = socket.create_connection((hostname, port), timeout=timeout)
    raw_socket.setblocking(False)
    connection = SSL.Connection(context, raw_socket)
    try:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            connection.set_tlsext_host_name(hostname.encode("idna"))
        connection.set_connect_state()
        deadline = time.monotonic() + timeout
        while True:
            try:
                connection.do_handshake()
                break
            except SSL.WantReadError:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([raw_socket], [], [], remaining)[0]:
                    raise TimeoutError("TLS handshake timed out while waiting to read.")
            except SSL.WantWriteError:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([], [raw_socket], [], remaining)[1]:
                    raise TimeoutError("TLS handshake timed out while waiting to write.")
        chain = connection.get_peer_cert_chain(as_cryptography=True) or []
        if not chain:
            raise ConnectionError("The server did not present a certificate chain.")
        return (
            connection.get_protocol_version_name() or "unknown",
            connection.get_cipher_name() or "unknown",
            tuple(chain),
        )
    finally:
        try:
            connection.shutdown()
        except (SSL.Error, SSL.SysCallError):
            pass
        connection.close()


def inspect_certificate_chain(
    url: str,
    *,
    verify_tls: bool = True,
    timeout: float = 15.0,
) -> CertificateChainResult:
    """Inspect the chain presented during a new TLS handshake."""

    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    if parts.scheme != "https":
        raise ValueError("Certificate inspection requires an https:// URL.")
    if parts.hostname is None:
        raise ValueError("The URL must contain a hostname.")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    try:
        verified_protocol = ""
        verified_cipher = ""
        if verify_tls:
            verified_protocol, verified_cipher = _verified_handshake(
                parts.hostname,
                port,
                timeout,
            )
        protocol, cipher, chain = _presented_chain(parts.hostname, port, timeout)
    except (OSError, SSL.Error, ssl.SSLError, TimeoutError) as exc:
        raise ConnectionError(f"TLS certificate inspection failed: {exc}") from exc

    details = tuple(
        _certificate_details(certificate, position)
        for position, certificate in enumerate(chain)
    )
    return CertificateChainResult(
        url=normalized,
        hostname=parts.hostname,
        port=port,
        tls_verified=verify_tls,
        tls_version=verified_protocol or protocol,
        cipher=verified_cipher or cipher,
        certificates=details,
    )
