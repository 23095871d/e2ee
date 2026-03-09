"""
generate_certs.py - Generate self-signed TLS certificates for the secure IM server.

This script creates a self-signed CA certificate and a server certificate
signed by that CA. These are used for TLS encryption between client and server.
In a production system, you'd use a real CA (like Let's Encrypt).
For our project, self-signed certs are fine since we control both endpoints.
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_certificates(output_dir="certs"):
    """Generate a self-signed CA cert and a server cert signed by it."""

    os.makedirs(output_dir, exist_ok=True)

    # ---- Step 1: Generate the CA (Certificate Authority) key and cert ----
    # This acts as our own trusted root certificate
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # 2048-bit RSA key for the CA
    )

    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "HK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "COMP3334 Secure IM"),
        x509.NameAttribute(NameOID.COMMON_NAME, "COMP3334 Root CA"),
    ])

    # Build the CA certificate (valid for 1 year)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)  # self-signed, so issuer = subject
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
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
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Save the CA private key (PEM format)
    ca_key_path = os.path.join(output_dir, "ca_key.pem")
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save the CA certificate (PEM format)
    ca_cert_path = os.path.join(output_dir, "ca_cert.pem")
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # ---- Step 2: Generate the server key and cert (signed by our CA) ----
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    server_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "HK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "COMP3334 Secure IM"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    # Build the server certificate (valid for 1 year)
    # Include SAN (Subject Alternative Name) for localhost and 127.0.0.1
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)  # signed by our CA
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(
                    __import__("ipaddress").IPv4Address("127.0.0.1")
                ),
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())  # signed by CA's private key
    )

    # Save server private key
    server_key_path = os.path.join(output_dir, "server_key.pem")
    with open(server_key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save server certificate
    server_cert_path = os.path.join(output_dir, "server_cert.pem")
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Certificates generated successfully!")
    print(f"    CA cert:     {ca_cert_path}")
    print(f"    CA key:      {ca_key_path}")
    print(f"    Server cert: {server_cert_path}")
    print(f"    Server key:  {server_key_path}")


if __name__ == "__main__":
    generate_certificates()
