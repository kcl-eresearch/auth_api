import sys
import traceback
import subprocess
import importlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from auth_api.common import get_db
from auth_api.ldap import init_ldap, get_ldap_user, format_name
from flask import current_app

"""
Get ID from database of relevant user - creating new entry if required
"""


def get_user_id(username):
    db = get_db()

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT id, deleted_at FROM users WHERE username = %s", (username,)
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write("Querying database for user failed:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    if len(result) == 1:
        if result[0]["deleted_at"] == None:
            return result[0]["id"]
        else:
            return False

    try:
        if not init_ldap():
            return False

        ldap_user = get_ldap_user(username)
    except Exception:
        sys.stderr.write("Querying LDAP for user failed:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    if ldap_user == {}:
        return 0

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users(username, display_name, email, created_at) VALUES(%s, %s, %s, NOW())",
                (username, format_name(ldap_user), ldap_user["mail"][0]),
            )
        db.commit()

        with db.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write("Adding new user to database failed:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    if len(result) == 1:
        return result[0]["id"]

    sys.stderr.write("Could not find new user in database\n")
    return False


"""
Get a user's SSH keys
"""


def get_user_ssh_keys(username):
    db = get_db()

    user_id = get_user_id(username)
    if not user_id:
        return False

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT id, created_at, name, type, pub_key, allowed_ips, access_type, extra_options FROM ssh_keys WHERE user_id = %s",
                (user_id,),
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write(f"Error getting ssh keys for {username}:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return result


"""
Get a user's VPN certs from database
"""


def get_user_vpn_keys(username):
    db = get_db()

    user_id = get_user_id(username)
    if not user_id:
        return False

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT created_at, expires_at, uuid, name, public_cert, status FROM vpn_keys WHERE user_id = %s",
                (user_id,),
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write(f"Error getting VPN certs for {username}:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return result


"""
Revoke a VPN key
"""


def revoke_vpn_key(username, key_name):
    db = get_db()
    config = current_app.config

    ca_provider = importlib.import_module(config["authapi"]["ca_provider"])

    user_id = get_user_id(username)
    if not user_id:
        return False

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT id, public_cert FROM vpn_keys WHERE status = 'active' AND user_id = %s AND name = %s",
                (user_id, key_name),
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write(
            f"Failed getting data for user {username} certificate {key_name}:\n"
        )
        sys.stderr.write(traceback.format_exc())
        return False

    for certificate in result:
        if ca_provider.revoke_vpn_cert(certificate["public_cert"]):
            try:
                with db.cursor() as cursor:
                    cursor.execute(
                        "UPDATE vpn_keys SET status = 'revoked' WHERE id = %s",
                        (certificate["id"],),
                    )
                db.commit()
            except Exception:
                sys.stderr.write(
                    f"Failed setting revocation status in database for user {username} certificate {key_name}:\n"
                )
                sys.stderr.write(traceback.format_exc())
                return False
        else:
            return False

    return True


"""
Get user MFA requests from database
"""


def get_mfa_requests(username, service="all"):
    user_id = get_user_id(username)
    if not user_id:
        return False

    db = get_db()
    requests = []
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT id, created_at, updated_at, expires_at, service, remote_ip, status FROM mfa_requests WHERE user_id = %s AND (created_at > NOW() - INTERVAL 7 DAY OR expires_at > NOW())",
                (user_id,),
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write(f"Failed getting {service} MFA requests for {username}:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    for request in result:
        if service == "all" or service == request["service"]:
            requests.append(request)

    return requests


"""
Get all current MFA requests from database
"""


def get_mfa_requests_all(service="all"):
    db = get_db()
    requests = []
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT users.username, mfa_requests.created_at, mfa_requests.updated_at, mfa_requests.expires_at, mfa_requests.service, mfa_requests.remote_ip, mfa_requests.status FROM mfa_requests INNER JOIN users ON mfa_requests.user_id = users.id WHERE expires_at IS NULL OR expires_at > NOW()"
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write(f"Failed getting {service} MFA requests:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    for request in result:
        if service == "all" or service == request["service"]:
            requests.append(request)

    return requests
