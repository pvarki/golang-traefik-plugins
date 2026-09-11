#!/usr/bin/env python3
"""Regenerate the OCSP interoperability fixtures in this directory.

These fixtures are produced by ``cryptography`` -- the same library the
rasenmaeher-api OCSP responder uses (see
``rasenmaeher_api/cert/cert_manager/ocsp/{signer,responder}.py``). They pin the
two things that must agree with the real responder: the SHA-256 CertID hashes,
and the RFC 8954 nonce echoed in responseExtensions.

Run with any interpreter that has ``cryptography`` installed, e.g. the
rasenmaeher-api virtualenv:

    python-rasenmaeher-api/.venv/bin/python testdata/generate.py
"""

import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

OUT = pathlib.Path(__file__).parent
LEAF_SERIAL = 0x4242
# Mirrors responder.py: thisUpdate = now-60s, nextUpdate = now + ocsp_response_validity.
RESPONSE_VALIDITY = datetime.timedelta(seconds=3600)


def digest(data: bytes) -> bytes:
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data)
    return hasher.finalize()


def main() -> None:
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "xcheck-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 20))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ALPHA01")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(LEAF_SERIAL)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 20))
        .sign(ca_key, hashes.SHA256())
    )

    (OUT / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (OUT / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))

    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(leaf, ca, hashes.SHA256())
        .add_extension(x509.OCSPNonce(bytes(range(16))), critical=False)
        .build()
    )
    (OUT / "request.der").write_bytes(request.public_bytes(serialization.Encoding.DER))
    nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    (OUT / "nonce.hex").write_text(nonce.hex() + "\n")

    # The issuer hashes signer.py computes; ocsp.go must reproduce these.
    assert request.issuer_name_hash == digest(ca.subject.public_bytes())
    assert request.issuer_key_hash == digest(
        ca.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
    )

    this_update = now - datetime.timedelta(seconds=60)
    next_update = now + RESPONSE_VALIDITY
    revoked_at = (now - datetime.timedelta(minutes=30)).replace(tzinfo=None)

    def build(status, revocation_time=None, reason=None) -> bytes:
        builder = (
            ocsp.OCSPResponseBuilder()
            .add_response_by_hash(
                issuer_name_hash=request.issuer_name_hash,
                issuer_key_hash=request.issuer_key_hash,
                algorithm=request.hash_algorithm,
                serial_number=request.serial_number,
                cert_status=status,
                this_update=this_update,
                next_update=next_update,
                revocation_time=revocation_time,
                revocation_reason=reason,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, ca)
            .add_extension(x509.OCSPNonce(nonce), critical=False)
        )
        return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    (OUT / "response_good.der").write_bytes(build(ocsp.OCSPCertStatus.GOOD))
    (OUT / "response_revoked.der").write_bytes(
        build(ocsp.OCSPCertStatus.REVOKED, revoked_at, x509.ReasonFlags.privilege_withdrawn)
    )
    (OUT / "response_unknown.der").write_bytes(build(ocsp.OCSPCertStatus.UNKNOWN))

    # The Go test pins "now" to this instant so the freshness check stays
    # meaningful without the fixtures expiring.
    (OUT / "generated_at.txt").write_text(now.isoformat().replace("+00:00", "Z") + "\n")
    (OUT / "revoked_at.txt").write_text(revoked_at.isoformat() + "Z\n")
    print(f"regenerated fixtures at {now.isoformat()}")


if __name__ == "__main__":
    main()
