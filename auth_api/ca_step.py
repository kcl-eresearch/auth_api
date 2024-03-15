import subprocess
import sys
import tempfile
import traceback
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import current_app

def issue_vpn_cert(cert_uuid):
    config = current_app.config

    tempdir = tempfile.mkdtemp(prefix="vpn_key_")
    path_crt = f"{tempdir}/{cert_uuid}.crt"
    path_key = f"{tempdir}/{cert_uuid}.key"

    try:
        subprocess.run(
            [
                config["ca"]["exe"],
                "ca",
                "certificate",
                "--provisioner",
                config["ca"]["provisioner"],
                "--provisioner-password-file",
                "/etc/auth_api/ca_password.txt",
                "--ca-url",
                config["ca"]["url"],
                "--root",
                config["ca"]["root_crt"],
                "--not-after",
                "%dh" % (24 * config["ca"]["cert_lifetime"]),
                "%s.%s" % (cert_uuid, config["ca"]["cert_domain"]),
                path_crt,
                path_key,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        sys.stderr.write("Failed generating VPN key/certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    try:
        with open(path_crt) as fh:
            data_crt = fh.read()
        with open(path_key) as fh:
            data_key = fh.read()
    except Exception:
        sys.stderr.write("Failed reading new VPN key/certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return([data_crt, data_key])

def revoke_vpn_cert(cert_pem):
    config = current_app.config

    cert_data = x509.load_pem_x509_certificate(
        cert_pem.encode(), default_backend()
    )
    serial_number = str(cert_data.serial_number)

    try:
        token = subprocess.run(
            [
                config["ca"]["exe"],
                "ca",
                "token",
                "--provisioner",
                config["ca"]["provisioner"],
                "--password-file",
                "/etc/auth_api/ca_password.txt",
                "--ca-url",
                config["ca"]["url"],
                "--root",
                config["ca"]["root_crt"],
                "--revoke",
                serial_number,
            ],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()
    except Exception:
        sys.stderr.write("Failed getting revocation token:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    try:
        subprocess.run(
            [
                config["ca"]["exe"],
                "ca",
                "revoke",
                serial_number,
                "--token",
                token
            ],
            capture_output=True,
            text=True,
            check=True
        )
    except Exception:
        sys.stderr.write("Failed revoking certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return True

def get_crl():
    return None # Step CA doesn't support this
