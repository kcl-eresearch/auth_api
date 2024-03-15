import hvac
import sys
import traceback
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import current_app

def convert_serial(serial_int):
    serial_hex = "%040x" % serial_int
    output = ""
    for i in range(19):
        output += "%s:" % serial_hex[i*2:i*2+2]
    output += serial_hex[38:40]
    return output

def issue_vpn_cert(cert_uuid):
    config = current_app.config
    vault_url = "https://%s:%d" % (config["ca"]["host"], config["ca"]["port"])

    try:
        client = hvac.Client(
            url=vault_url,
            verify=config["ca"]["tls_verify"]
        )
        client.auth.userpass.login(
            username=config["ca"]["username"],
            password=config["ca"]["password"]
        )
    except Exception:
        sys.stderr.write("Failed connecting to Vault server %s:\n" % vault_url)
        sys.stderr.write(traceback.format_exc())
        return False

    if not client.is_authenticated():
        sys.stderr.write("Vault authentication failed\n")
        return False

    try:
        result = client.secrets.pki.generate_certificate(
            name=config["ca"]["role"],
            common_name="%s.%s" % (cert_uuid, config["ca"]["cert_domain"]),
            extra_params={"ttl": "%dd" % config["ca"]["cert_lifetime"]}
        )
    except Exception:
        sys.stderr.write("Failed generating certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return(
        [
            "%s\n%s" % (result["data"]["certificate"], result["data"]["issuing_ca"]),
            result["data"]["private_key"]
        ]
    )

def revoke_vpn_cert(cert_pem):
    config = current_app.config
    vault_url = "https://%s:%d" % (config["ca"]["host"], config["ca"]["port"])

    try:
        cert_data = x509.load_pem_x509_certificate(
            cert_pem.encode(), default_backend()
        )
    except Exception:
        sys.stderr.write("Could not parse certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    try:
        serial_number = convert_serial(cert_data.serial_number)
    except Exception:
        sys.stderr.write("Could not obtain serial number:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    try:
        client = hvac.Client(
            url=vault_url,
            verify=config["ca"]["tls_verify"]
        )
        client.auth.userpass.login(
            username=config["ca"]["username"],
            password=config["ca"]["password"]
        )
    except Exception:
        sys.stderr.write("Failed connecting to Vault server %s:\n" % vault_url)
        sys.stderr.write(traceback.format_exc())
        return False

    if not client.is_authenticated():
        sys.stderr.write("Vault authentication failed\n")
        return False

    try:
        client.secrets.pki.revoke_certificate(
            serial_number=serial_number
        )
    except Exception:
        sys.stderr.write("Failed to revoke certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return True

def get_crl():
    config = current_app.config
    vault_url = "https://%s:%d" % (config["ca"]["host"], config["ca"]["port"])

    try:
        client = hvac.Client(
            url=vault_url,
            verify=config["ca"]["tls_verify"]
        )
        client.auth.userpass.login(
            username=config["ca"]["username"],
            password=config["ca"]["password"]
        )
    except Exception:
        sys.stderr.write("Failed connecting to Vault server %s:\n" % vault_url)
        sys.stderr.write(traceback.format_exc())
        return False

    if not client.is_authenticated():
        sys.stderr.write("Vault authentication failed\n")
        return False

    try:
        crl = client.secrets.pki.read_crl()
    except Exception:
        sys.stderr.write("Failed to retrieve CRL:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return crl
