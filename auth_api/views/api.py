import datetime
import jinja2
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import traceback
import uuid
from auth_api.common import make_serializable, send_email, get_db, validate_ssh_key
from auth_api.user import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Blueprint, current_app, Response, request

api_v1 = Blueprint("apiv1", __name__, url_prefix="/api/v1")


"""
Authenticate request based on path, method and user
"""


def auth_request(path, method, user):
    # Deny anonymous access
    if user in ["", None]:
        sys.stderr.write("Access denied: empty username\n")
        return False

    # Allow anyone to access status page
    if re.match(r"^/v[0-9]+/status$", path):
        return True

    # Deny users not in config file
    user_valid = False
    for k, v in current_app.config["authapi"].items():
        if re.match(r"^auth_user_", k) and user == v:
            user_valid = True
            break

    if not user_valid:
        sys.stderr.write(f"Access denied: username {user} not valid\n")
        return False

    # Handle bogus paths
    m = re.match(
        r"^/api/v[0-9]+/([a-z_]+)(/[a-z0-9_]+(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?)?",
        path,
    )
    if not m:
        sys.stderr.write(f"Access denied for {user}: invalid API path: {path}\n")
        return False

    req_function = m.group(1)

    permissions = {
        current_app.config["authapi"]["auth_user_web"]: [
            ("ssh_keys", "GET"),
            ("ssh_keys", "PUT"),
            ("vpn_keys", "GET"),
            ("vpn_keys", "POST"),
            ("vpn_keys", "DELETE"),
            ("mfa_requests", "GET"),
            ("mfa_requests", "POST"),
        ],
        current_app.config["authapi"]["auth_user_bastion"]: [
            ("ssh_auth", "GET"),
            ("ssh_auth_no_mfa", "GET"),
            ("ssh_keys", "GET"),
            ("vpn_auth", "GET"),
        ],
        current_app.config["authapi"]["auth_user_maint"]: [("maint", "POST")],
        current_app.config["authapi"]["auth_user_admin"]: [
            ("ssh_keys", "GET"),
            ("vpn_keys", "GET"),
            ("mfa_requests", "GET"),
        ],
    }

    if (req_function, method) in permissions[user]:
        return True

    sys.stderr.write("Access denied: no valid permissions\n")


"""
Encode response as JSON and return it via Flask
"""


def api_response(data, code=200):
    resp = Response(json.dumps(data), status=code, content_type="application/json")
    return resp


"""
Initalise and authenticate
"""


@api_v1.before_request
def apiv1_before_request():
    if not auth_request(request.path, request.method, request.remote_user):
        return api_response({"status": "ERROR", "detail": "Forbidden"}, 403)


"""
Handle 404s (though normally should get permissions error first)
"""


@api_v1.errorhandler(404)
def api_not_found(e):
    return api_response({"status": "ERROR", "detail": "Not found"}, 404)


"""
Status if nothing requested - also used for monitoring
"""


@api_v1.route("/status")
def api_status():
    db = get_db()

    table_counts = {}
    for table in ["users", "mfa_requests", "ssh_keys", "vpn_keys"]:
        try:
            with db.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) AS table_count FROM {table}")
                result = cursor.fetchall()
        except Exception as e:
            sys.stderr.write(f"Error getting status (count of {table} table):\n")
            sys.stderr.write(traceback.format_exc())
            return api_response(
                {"status": "ERROR", "detail": f"Failed getting {table} count: {e}"}, 500
            )

        table_counts[table] = result[0]["table_count"]

    return api_response(
        {
            "status": "OK",
            "table_counts": table_counts,
            "host": socket.getfqdn(),
            "version": 1,
        }
    )


"""
Return a list of user's SSH public keys
"""


@api_v1.route(f"/ssh_keys/<username>", methods=["GET"])
def api_get_ssh_keys(username):
    keys = get_user_ssh_keys(username)
    if keys == False:
        return api_response(
            {"status": "ERROR", "detail": "SSH key retrieval failed"}, 500
        )

    return api_response({"status": "OK", "keys": make_serializable(keys)})


"""
Return a list of user's VPN keys
"""


@api_v1.route(f"/vpn_keys/<username>", methods=["GET"])
def api_get_vpn_keys(username):
    keys = get_user_vpn_keys(username)
    if keys == False:
        return api_response(
            {"status": "ERROR", "detail": "VPN key retrieval failed"}, 500
        )

    return api_response({"status": "OK", "keys": make_serializable(keys)})


"""
Create new OpenVPN key/certificate
"""


@api_v1.route(f"/vpn_keys/<username>/<key_name>", methods=["POST"])
def api_set_vpn_key(username, key_name):
    config = current_app.config

    user_id = get_user_id(username)
    if not user_id:
        return api_response({"status": "ERROR", "detail": "User not found"}, 404)

    cert_uuid = str(uuid.uuid1())
    tempdir = tempfile.mkdtemp(prefix="vpn_key_")
    path_crt = f"{tempdir}/{cert_uuid}.crt"
    path_key = f"{tempdir}/{cert_uuid}.key"

    try:
        with open(
            os.path.join(config["templates_path"], "vpn_template.j2")
        ) as fh:
            vpn_template = jinja2.Template(fh.read())
    except Exception:
        sys.stderr.write("Failed loading VPN config template:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500
        )

    try:
        with open(config["ca"]["root_crt"]) as fh:
            ca_cert = fh.read()
    except Exception:
        sys.stderr.write("Failed loading CA cert:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500
        )

    try:
        subprocess.check_output(
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
                cert_uuid,
                path_crt,
                path_key,
            ],
            stderr=subprocess.STDOUT,
        )
    except Exception:
        sys.stderr.write("Failed generating VPN key/certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500
        )

    try:
        with open(path_crt) as fh:
            data_crt = fh.read()
        with open(path_key) as fh:
            data_key = fh.read()
    except Exception:
        sys.stderr.write("Failed reading new VPN key/certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "VPN key/certificate read failed"}, 500
        )

    try:
        cert = x509.load_pem_x509_certificate(
            data_crt.encode("utf8"), default_backend()
        )
    except Exception:
        sys.stderr.write("Failed decoding new certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "VPN key/certificate decode failed"}, 500
        )

    if not revoke_vpn_key(username, key_name):
        return api_response(
            {"status": "ERROR", "detail": "Old VPN key/certificate revocation failed"},
            500,
        )

    try:
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute(
                "INSERT INTO vpn_keys(created_at, expires_at, user_id, uuid, name, public_cert, status) VALUES(%s, %s, %s, %s, %s, %s, 'active')",
                (
                    cert.not_valid_before_utc,
                    cert.not_valid_after_utc,
                    user_id,
                    cert_uuid,
                    key_name,
                    data_crt,
                ),
            )
        db.commit()
    except Exception:
        sys.stderr.write("Failed storing certificate in database:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {
                "status": "ERROR",
                "detail": "VPN key/certificate database storage failed",
            },
            500,
        )

    shutil.rmtree(tempdir)

    vpn_config = vpn_template.render(
        cert_uuid=cert_uuid,
        cert_created=cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
        cert_expires=cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        ca_cert=ca_cert.strip(),
        public_cert=data_crt.strip(),
        private_key=data_key.strip(),
    )

    send_email(username, "vpn")
    return api_response(
        {
            "status": "OK",
            "public_cert": data_crt,
            "private_key": data_key,
            "created_at": int(cert.not_valid_before_utc.timestamp()),
            "expires_at": int(cert.not_valid_after_utc.timestamp()),
            "name": key_name,
            "status": "active",
            "uuid": cert_uuid,
            "config": vpn_config,
        }
    )


"""
Revoke an OpenVPN key/certificate
"""


@api_v1.route(f"/vpn_keys/<username>/<key_name>", methods=["DELETE"])
def api_revoke_vpn_key(username, key_name):
    user_id = get_user_id(username)
    if not user_id:
        return api_response({"status": "ERROR", "detail": "User not found"}, 404)

    if not revoke_vpn_key(username, key_name):
        return api_response({"status": "ERROR", "detail": "Revocation failed"}, 500)

    send_email(username, "vpn")
    return api_get_vpn_keys(username)


"""
Set a user's SSH keys
"""


@api_v1.route(f"/ssh_keys/<username>", methods=["PUT"])
def api_set_user_ssh_keys(username):
    config = current_app.config

    user_id = get_user_id(username)
    if not user_id:
        return api_response({"status": "ERROR", "detail": "User not found"}, 404)

    existing = get_user_ssh_keys(username)
    if existing == False:
        return api_response(
            {"status": "ERROR", "detail": "User validation failed"}, 500
        )

    existing_named = {}
    for key in existing:
        existing_named[key["name"]] = key

    ssh_keys = request.json
    if not isinstance(ssh_keys, dict):
        return api_response({"status": "ERROR", "detail": "Invalid key list"}, 400)

    db = get_db()
    try:
        with db.cursor() as cursor:
            for name, key in ssh_keys.items():
                if name == "" or not isinstance(name, str):
                    return api_response(
                        {"status": "ERROR", "detail": "Invalid key name"}, 400
                    )

                if (
                    "type" not in key
                    or key["type"] not in config["authapi"]["ssh_key_types"]
                ):
                    return api_response(
                        {"status": "ERROR", "detail": "Invalid key type"}, 400
                    )

                if "pub_key" not in key:
                    return api_response(
                        {"status": "ERROR", "detail": "Invalid key data"}, 400
                    )

                if not validate_ssh_key(key["type"], key["pub_key"], name):
                    return api_response(
                        {"status": "ERROR", "detail": "Invalid key data"}, 400
                    )

                if "access_type" in key and key["access_type"] != "any":
                    if "allowed_ips" not in key or key["allowed_ips"] in [None, "", []]:
                        return api_response(
                            {
                                "status": "ERROR",
                                "detail": "Invalid allowed_ips for service account",
                            },
                            400,
                        )

                if (
                    name not in existing_named
                    or existing_named[name]["type"] != key["type"]
                    or existing_named[name]["pub_key"] != key["pub_key"]
                ):
                    cursor.execute(
                        "DELETE FROM ssh_keys WHERE user_id = %s AND name = %s",
                        (user_id, name),
                    )
                    if "allowed_ips" in key:
                        allowed_ips = json.dumps(key["allowed_ips"])
                    else:
                        allowed_ips = None
                    if "access_type" in key:
                        access_type = key["access_type"]
                    else:
                        access_type = "any"
                    cursor.execute(
                        "INSERT INTO ssh_keys(created_at, user_id, type, name, pub_key, allowed_ips, access_type) VALUES(NOW(), %s, %s, %s, %s, %s, %s)",
                        (
                            user_id,
                            key["type"],
                            name,
                            key["pub_key"],
                            allowed_ips,
                            access_type,
                        ),
                    )

            for name, data in existing_named.items():
                if name not in ssh_keys:
                    cursor.execute(
                        "DELETE FROM ssh_keys WHERE user_id = %s AND name = %s",
                        (user_id, name),
                    )

        db.commit()

    except Exception:
        sys.stderr.write("Failed saving SSH keys:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "Failed saving SSH keys"}, 500
        )

    send_email(username, "ssh")
    return api_get_ssh_keys(username)


"""
Get user's MFA requests
"""


@api_v1.route(f"/mfa_requests/<username>", methods=["GET"])
def api_get_mfa_requests(username):
    user_id = get_user_id(username)
    if not user_id:
        return api_response({"status": "ERROR", "detail": "User not found"}, 404)

    mfa_requests = get_mfa_requests(username)
    if mfa_requests == False:
        return api_response(
            {"status": "ERROR", "detail": "MFA request retrieval failed"}, 500
        )

    return api_response(
        {"status": "OK", "mfa_requests": make_serializable(mfa_requests)}
    )


"""
Get all users' MFA requests
"""


@api_v1.route(f"/mfa_requests", methods=["GET"])
def api_get_mfa_requests_all():
    mfa_requests = get_mfa_requests_all()
    if mfa_requests == False:
        return api_response(
            {"status": "ERROR", "detail": "MFA request retrieval failed"}, 500
        )

    return api_response(
        {"status": "OK", "mfa_requests": make_serializable(mfa_requests)}
    )


"""
Approve (or reject) user MFA request
"""


@api_v1.route(f"/mfa_requests/<username>", methods=["POST"])
def api_set_mfa_request(username):
    config = current_app.config
    user_id = get_user_id(username)
    if not user_id:
        return api_response({"status": "ERROR", "detail": "User not found"}, 404)

    mfa_request = request.json
    if not isinstance(mfa_request, dict):
        return api_response(
            {"status": "ERROR", "detail": "Invalid MFA request - not a dict"}, 400
        )

    if "ip_address" not in mfa_request:
        return api_response(
            {"status": "ERROR", "detail": "Invalid MFA request - missing ip_address"},
            400,
        )

    if "service" not in mfa_request:
        return api_response(
            {"status": "ERROR", "detail": "Invalid MFA request - missing service"}, 400
        )

    if mfa_request["service"] not in ["ssh", "vpn"]:
        return api_response(
            {"status": "ERROR", "detail": "Invalid MFA request - invalid service"}, 400
        )

    if "status" not in mfa_request:
        return api_response(
            {"status": "ERROR", "detail": "Invalid MFA request - missing status"}, 400
        )

    if mfa_request["status"] not in ["approved", "rejected"]:
        return api_response(
            {"status": "ERROR", "detail": "Invalid MFA request - invalid status"}, 400
        )

    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "UPDATE mfa_requests SET status = %s, updated_at = NOW(), expires_at = %s WHERE user_id = %s AND service = %s AND remote_ip = %s AND (expires_at IS NULL OR expires_at > NOW())",
                (
                    mfa_request["status"],
                    datetime.datetime.now()
                    + datetime.timedelta(
                        minutes=config["authapi"]["mfa_timeout"][mfa_request["status"]]
                    ),
                    user_id,
                    mfa_request["service"],
                    mfa_request["ip_address"],
                ),
            )
        db.commit()
    except Exception:
        sys.stderr.write(f"Failed updating MFA request for {username}:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "Failed saving MFA request"}, 500
        )

    return api_get_mfa_requests(username)


"""
Authenticate user VPN access
"""


@api_v1.route(f"/vpn_auth/<cert_cn>/<ip_address>", methods=["GET"])
def api_auth_vpn_access(cert_cn, ip_address):
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT vpn_keys.expires_at, vpn_keys.status, vpn_keys.user_id, users.username, users.deleted_at FROM vpn_keys INNER JOIN users ON vpn_keys.user_id = users.id WHERE vpn_keys.uuid = %s",
                (cert_cn,),
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write(f"Failed checking certificate {cert_cn}:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response(
            {"status": "ERROR", "detail": "Failed checking certificate"}, 500
        )

    if len(result) != 1:
        return api_response(
            {"status": "OK", "result": "REJECT", "reason": "certificate unknown"}
        )

    user_id = result[0]["user_id"]
    username = result[0]["username"]

    if result[0]["expires_at"] < datetime.datetime.now():
        return api_response(
            {
                "status": "OK",
                "result": "REJECT",
                "reason": "certificate expired",
                "username": username,
            }
        )

    if result[0]["status"] != "active":
        return api_response(
            {
                "status": "OK",
                "result": "REJECT",
                "reason": "certificate revoked",
                "username": username,
            }
        )

    if result[0]["deleted_at"] != None:
        return api_response(
            {
                "status": "OK",
                "result": "REJECT",
                "reason": "user deleted",
                "username": username,
            }
        )

    ip_address_found = False
    mfa_requests = get_mfa_requests(username, "vpn")
    for request in mfa_requests:
        if request["remote_ip"] == ip_address:
            ip_address_found = True
            if (
                request["status"] == "approved"
                and request["expires_at"] > datetime.datetime.now()
            ):
                return api_response(
                    {"status": "OK", "result": "ACCEPT", "username": username}
                )

            if request["status"] == "rejected":
                return api_response(
                    {
                        "status": "OK",
                        "result": "REJECT",
                        "reason": "MFA rejected",
                        "username": username,
                    }
                )

    if not ip_address_found:
        try:
            with db.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO mfa_requests(created_at, updated_at, user_id, service, remote_ip) VALUES(NOW(), NOW(), %s, 'vpn', %s)",
                    (user_id, ip_address),
                )
            db.commit()
        except Exception:
            sys.stderr.write(
                f"Failed storing mfa_request for {username} at {ip_address}:\n"
            )
            sys.stderr.write(traceback.format_exc())
            return api_response(
                {"status": "ERROR", "detail": "Failed storing MFA request"}, 500
            )

    return api_response(
        {
            "status": "OK",
            "result": "PENDING",
            "reason": "MFA not approved",
            "username": username,
        }
    )


"""
Authenticate user SSH access
"""


@api_v1.route(f"/ssh_auth/<username>/<ip_address>", methods=["GET"])
def api_auth_ssh_access(username, ip_address):
    user_id = get_user_id(username)
    if not user_id:
        return api_response({"status": "ERROR", "detail": "User not found"}, 404)

    db = get_db()

    ip_address_found = False
    mfa_requests = get_mfa_requests(username, "ssh")
    for request in mfa_requests:
        if request["remote_ip"] == ip_address and (
            request["expires_at"] == None
            or request["expires_at"] > datetime.datetime.now()
        ):
            ip_address_found = True
            if request["status"] == "approved":
                keys = get_user_ssh_keys(username)
                if keys == False:
                    return api_response(
                        {"status": "ERROR", "detail": "SSH key retrieval failed"}, 500
                    )
                return api_response(
                    {
                        "status": "OK",
                        "result": "ACCEPT",
                        "keys": make_serializable(keys),
                    }
                )

            if request["status"] == "rejected":
                return api_response(
                    {"status": "OK", "result": "REJECT", "reason": "MFA rejected"}
                )

    if not ip_address_found:
        try:
            with db.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO mfa_requests(created_at, updated_at, user_id, service, remote_ip) VALUES(NOW(), NOW(), %s, 'ssh', %s)",
                    (user_id, ip_address),
                )
            db.commit()
        except Exception:
            sys.stderr.write(
                f"Failed storing mfa_request for {username} at {ip_address}:\n"
            )
            sys.stderr.write(traceback.format_exc())
            return api_response(
                {"status": "ERROR", "detail": "Failed storing MFA request"}, 500
            )

    return api_response(
        {"status": "OK", "result": "PENDING", "reason": "MFA not approved"}
    )


"""
Authenticate user SSH access without MFA
"""


@api_v1.route(f"/ssh_auth_no_mfa/<username>", methods=["GET"])
def api_auth_ssh_access_no_mfa(username):
    config = current_app.config
    keys = get_user_ssh_keys(username)
    if keys == False:
        return api_response(
            {"status": "ERROR", "detail": "SSH key retrieval failed"}, 500
        )

    is_service_account = False
    for regex in config["authapi"]["service_account_regex"]:
        if re.match(regex, username):
            is_service_account = True
    if is_service_account:
        valid_keys = []
        for key in keys:
            if key["access_type"] == "any":
                continue

            if key["allowed_ips"] == None:
                continue

            try:
                allowed_ips = json.loads(key["allowed_ips"])
            except:
                continue

            if type(allowed_ips) != list:
                continue

            if len(allowed_ips) == 0:
                continue

            valid_keys.append(key)

    else:
        valid_keys = keys

    return api_response({"status": "OK", "keys": make_serializable(valid_keys)})


"""
Update users table
"""


@api_v1.route(f"/maint/update_users", methods=["POST"])
def api_update_users():
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT username, display_name, email, deleted_at FROM users"
            )
            db_users = cursor.fetchall()
    except Exception:
        sys.stderr.write("Failed getting users:\n")
        sys.stderr.write(traceback.format_exc())
        return api_response({"status": "ERROR", "detail": "Failed getting users"}, 500)

    if not init_ldap():
        return api_response(
            {"status": "ERROR", "detail": "Failed LDAP connection"}, 500
        )

    changes = 0

    with db.cursor() as cursor:
        for user_db in db_users:
            username = user_db["username"]
            user_ad = get_ldap_user(username)
            if user_db["deleted_at"] == None:
                if user_ad == {} or int(user_ad["userAccountControl"][0]) & 2 == 2:
                    cursor.execute(
                        "UPDATE users SET deleted_at = NOW(), updated_at = NOW() WHERE username = %s",
                        (username,),
                    )
                    changes += 1
            else:
                if user_ad != {} and int(user_ad["userAccountControl"][0]) & 2 == 0:
                    cursor.execute(
                        "UPDATE users SET deleted_at = NULL, updated_at = NOW() WHERE username = %s",
                        (username,),
                    )
                    changes += 1

            if (
                user_ad != {}
                and format_name(user_ad).decode() != user_db["display_name"]
            ):
                cursor.execute(
                    "UPDATE users SET updated_at = NOW(), display_name = %s WHERE username = %s",
                    (format_name(user_ad), username),
                )
                changes += 1

            if user_ad != {} and user_ad["mail"][0].decode() != user_db["email"]:
                cursor.execute(
                    "UPDATE users SET updated_at = NOW(), email = %s WHERE username = %s",
                    (user_ad["mail"][0], username),
                )
                changes += 1

    db.commit()

    return api_response({"status": "OK", "changes": changes})
