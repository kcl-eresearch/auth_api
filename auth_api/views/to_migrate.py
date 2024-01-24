from cryptography.hazmat.backends import default_backend
from cryptography import x509
from flask import g
import datetime
import flask
import jinja2
import json
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import traceback
import uuid
import yaml

'''
Return a list of user's SSH public keys
'''
@app.route(f"/v{API_VERSION}/ssh_keys/<username>", methods=["GET"])
def api_get_ssh_keys(username):
    keys = get_user_ssh_keys(username)
    if keys == False:
        return flask_response({"status": "ERROR", "detail": "SSH key retrieval failed"}, 500)

    return flask_response({"status": "OK", "keys": make_serializable(keys)})

'''
Return a list of user's VPN keys
'''
@app.route(f"/v{API_VERSION}/vpn_keys/<username>", methods=["GET"])
def api_get_vpn_keys(username):
    keys = get_user_vpn_keys(username)
    if keys == False:
        return flask_response({"status": "ERROR", "detail": "VPN key retrieval failed"}, 500)

    return flask_response({"status": "OK", "keys": make_serializable(keys)})

'''
Create new OpenVPN key/certificate
'''
@app.route(f"/v{API_VERSION}/vpn_keys/<username>/<key_name>", methods=["POST"])
def api_set_vpn_key(username, key_name):
    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    cert_uuid = str(uuid.uuid1())
    tempdir = tempfile.mkdtemp(prefix="vpn_key_")
    path_crt = f"{tempdir}/{cert_uuid}.crt"
    path_key = f"{tempdir}/{cert_uuid}.key"

    try:
        with open("/etc/auth_api/vpn_template.j2") as fh:
            vpn_template = jinja2.Template(fh.read())
    except Exception:
        sys.stderr.write("Failed loading VPN config template:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500)

    try:
        with open(config["ca"]["root_crt"]) as fh:
            ca_cert = fh.read()
    except Exception:
        sys.stderr.write("Failed loading CA cert:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500)

    try:
        output = subprocess.check_output([config["ca"]["exe"], "ca", "certificate", "--provisioner", config["ca"]["provisioner"], "--provisioner-password-file", "/etc/auth_api/ca_password.txt", "--ca-url", config["ca"]["url"], "--root", config["ca"]["root_crt"], "--not-after", "%dh" % (24 * config["ca"]["cert_lifetime"]), cert_uuid, path_crt, path_key], stderr=subprocess.STDOUT)
    except Exception:
        sys.stderr.write("Failed generating VPN key/certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500)

    try:
        with open(path_crt) as fh:
            data_crt = fh.read()
        with open(path_key) as fh:
            data_key = fh.read()
    except Exception:
        sys.stderr.write("Failed reading new VPN key/certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate read failed"}, 500)

    try:
        cert = x509.load_pem_x509_certificate(data_crt.encode('utf8'), default_backend())
    except Exception:
        sys.stderr.write("Failed decoding new certificate:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate decode failed"}, 500)

    if not revoke_vpn_key(username, key_name):
        return flask_response({"status": "ERROR", "detail": "Old VPN key/certificate revocation failed"}, 500)

    try:
        cursor = g.db_conn.cursor()
        cursor.execute("INSERT INTO vpn_keys(created_at, expires_at, user_id, uuid, name, public_cert, status) VALUES(%s, %s, %s, %s, %s, %s, 'active')", (cert.not_valid_before, cert.not_valid_after, user_id, cert_uuid, key_name, data_crt))
        g.db_conn.commit()
    except Exception:
        sys.stderr.write("Failed storing certificate in database:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate database storage failed"}, 500)

    shutil.rmtree(tempdir)

    vpn_config = vpn_template.render(
        cert_uuid=cert_uuid,
        cert_created=cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
        cert_expires=cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
        ca_cert=ca_cert.strip(),
        public_cert=data_crt.strip(),
        private_key=data_key.strip()
    )

    send_email(username, "vpn")
    return flask_response({"status": "OK", "public_cert": data_crt, "private_key": data_key, "created_at": int(cert.not_valid_before.timestamp()), "expires_at": int(cert.not_valid_after.timestamp()), "name": key_name, "status": "active", "uuid": cert_uuid, "config": vpn_config})

'''
Revoke an OpenVPN key/certificate
'''
@app.route(f"/v{API_VERSION}/vpn_keys/<username>/<key_name>", methods=["DELETE"])
def api_revoke_vpn_key(username, key_name):
    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    if not revoke_vpn_key(username, key_name):
        return flask_response({"status": "ERROR", "detail": "Revocation failed"}, 500)

    send_email(username, "vpn")
    return api_get_vpn_keys(username)

'''
Set a user's SSH keys
'''
@app.route(f"/v{API_VERSION}/ssh_keys/<username>", methods=["PUT"])
def api_set_user_ssh_keys(username):
    global config

    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    existing = get_user_ssh_keys(username)
    if existing == False:
        return flask_response({"status": "ERROR", "detail": "User validation failed"}, 500)

    existing_named = {}
    for key in existing:
        existing_named[key["name"]] = key

    ssh_keys = flask.request.json
    if not isinstance(ssh_keys, dict):
        return flask_response({"status": "ERROR", "detail": "Invalid key list"}, 400)

    try:
        cursor = g.db_conn.cursor()
        for name, key in ssh_keys.items():
            if name == "" or not isinstance(name, str):
                return flask_response({"status": "ERROR", "detail": "Invalid key name"}, 400)

            if "type" not in key or key["type"] not in config["main"]["ssh_key_types"]:
                return flask_response({"status": "ERROR", "detail": "Invalid key type"}, 400)

            if "pub_key" not in key:
                return flask_response({"status": "ERROR", "detail": "Invalid key data"}, 400)

            if not validate_ssh_key(key["type"], key["pub_key"], name):
                return flask_response({"status": "ERROR", "detail": "Invalid key data"}, 400)

            if "access_type" in key and key["access_type"] != "any":
                if "allowed_ips" not in key or key["allowed_ips"] in [None, "", []]:
                    return flask_response({"status": "ERROR", "detail": "Invalid allowed_ips for service account"}, 400)

            if name not in existing_named or existing_named[name]["type"] != key["type"] or existing_named[name]["pub_key"] != key["pub_key"]:
                cursor.execute("DELETE FROM ssh_keys WHERE user_id = %s AND name = %s", (user_id, name))
                if "allowed_ips" in key:
                    allowed_ips = json.dumps(key["allowed_ips"])
                else:
                    allowed_ips = None
                if "access_type" in key:
                    access_type = key["access_type"]
                else:
                    access_type = "any"
                cursor.execute("INSERT INTO ssh_keys(created_at, user_id, type, name, pub_key, allowed_ips, access_type) VALUES(NOW(), %s, %s, %s, %s, %s, %s)", (user_id, key["type"], name, key["pub_key"], allowed_ips, access_type))

        for name, data in existing_named.items():
            if name not in ssh_keys:
                cursor.execute("DELETE FROM ssh_keys WHERE user_id = %s AND name = %s", (user_id, name))

        g.db_conn.commit()

    except Exception:
        sys.stderr.write("Failed saving SSH keys:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "Failed saving SSH keys"}, 500)

    send_email(username, "ssh")
    return api_get_ssh_keys(username)

'''
Get user's MFA requests
'''
@app.route(f"/v{API_VERSION}/mfa_requests/<username>", methods=["GET"])
def api_get_mfa_requests(username):
    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    mfa_requests = get_mfa_requests(username)
    if mfa_requests == False:
        return flask_response({"status": "ERROR", "detail": "MFA request retrieval failed"}, 500)

    return flask_response({"status": "OK", "mfa_requests": make_serializable(mfa_requests)})

'''
Get all users' MFA requests
'''
@app.route(f"/v{API_VERSION}/mfa_requests", methods=["GET"])
def api_get_mfa_requests_all():
    mfa_requests = get_mfa_requests_all()
    if mfa_requests == False:
        return flask_response({"status": "ERROR", "detail": "MFA request retrieval failed"}, 500)

    return flask_response({"status": "OK", "mfa_requests": make_serializable(mfa_requests)})

'''
Approve (or reject) user MFA request
'''
@app.route(f"/v{API_VERSION}/mfa_requests/<username>", methods=["POST"])
def api_set_mfa_request(username):
    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    mfa_request = flask.request.json
    if not isinstance(mfa_request, dict):
        return flask_response({"status": "ERROR", "detail": "Invalid MFA request - not a dict"}, 400)

    if "ip_address" not in mfa_request:
        return flask_response({"status": "ERROR", "detail": "Invalid MFA request - missing ip_address"}, 400)

    if "service" not in mfa_request:
        return flask_response({"status": "ERROR", "detail": "Invalid MFA request - missing service"}, 400)

    if mfa_request["service"] not in ["ssh", "vpn"]:
        return flask_response({"status": "ERROR", "detail": "Invalid MFA request - invalid service"}, 400)

    if "status" not in mfa_request:
        return flask_response({"status": "ERROR", "detail": "Invalid MFA request - missing status"}, 400)

    if mfa_request["status"] not in ["approved", "rejected"]:
        return flask_response({"status": "ERROR", "detail": "Invalid MFA request - invalid status"}, 400)

    try:
        cursor = g.db_conn.cursor()
        cursor.execute("UPDATE mfa_requests SET status = %s, updated_at = NOW(), expires_at = %s WHERE user_id = %s AND service = %s AND remote_ip = %s AND (expires_at IS NULL OR expires_at > NOW())", (mfa_request["status"], datetime.datetime.now() + datetime.timedelta(minutes=config["main"]["mfa_timeout"][mfa_request["status"]]), user_id, mfa_request["service"], mfa_request["ip_address"]))
        g.db_conn.commit()
    except Exception:
        sys.stderr.write(f"Failed updating MFA request for {username}:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "Failed saving MFA request"}, 500)

    return api_get_mfa_requests(username)

'''
Authenticate user VPN access
'''
@app.route(f"/v{API_VERSION}/vpn_auth/<cert_cn>/<ip_address>", methods=["GET"])
def api_auth_vpn_access(cert_cn, ip_address):
    try:
        cursor = g.db_conn.cursor(dictionary=True)
        cursor.execute("SELECT vpn_keys.expires_at, vpn_keys.status, vpn_keys.user_id, users.username, users.deleted_at FROM vpn_keys INNER JOIN users ON vpn_keys.user_id = users.id WHERE vpn_keys.uuid = %s", (cert_cn,))
        result = cursor.fetchall()
    except Exception:
        sys.stderr.write(f"Failed checking certificate {cert_cn}:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "Failed checking certificate"}, 500)

    if len(result) != 1:
        return flask_response({"status": "OK", "result": "REJECT", "reason": "certificate unknown"})

    user_id = result[0]["user_id"]
    username = result[0]["username"]

    if result[0]["expires_at"] < datetime.datetime.now():
        return flask_response({"status": "OK", "result": "REJECT", "reason": "certificate expired", "username": username})

    if result[0]["status"] != "active":
        return flask_response({"status": "OK", "result": "REJECT", "reason": "certificate revoked", "username": username})

    if result[0]["deleted_at"] != None:
        return flask_response({"status": "OK", "result": "REJECT", "reason": "user deleted", "username": username})

    ip_address_found = False
    mfa_requests = get_mfa_requests(username, "vpn")
    for request in mfa_requests:
        if request["remote_ip"] == ip_address:
            ip_address_found = True
            if request["status"] == "approved" and request["expires_at"] > datetime.datetime.now():
                return flask_response({"status": "OK", "result": "ACCEPT", "username": username})

            if request["status"] == "rejected":
                return flask_response({"status": "OK", "result": "REJECT", "reason": "MFA rejected", "username": username})

    if not ip_address_found:
        try:
            cursor = g.db_conn.cursor()
            cursor.execute("INSERT INTO mfa_requests(created_at, updated_at, user_id, service, remote_ip) VALUES(NOW(), NOW(), %s, 'vpn', %s)", (user_id, ip_address))
            g.db_conn.commit()
        except Exception:
            sys.stderr.write(f"Failed storing mfa_request for {username} at {ip_address}:\n")
            sys.stderr.write(traceback.format_exc())
            return flask_response({"status": "ERROR", "detail": "Failed storing MFA request"}, 500)

    return flask_response({"status": "OK", "result": "PENDING", "reason": "MFA not approved", "username": username})

'''
Authenticate user SSH access
'''
@app.route(f"/v{API_VERSION}/ssh_auth/<username>/<ip_address>", methods=["GET"])
def api_auth_ssh_access(username, ip_address):
    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    ip_address_found = False
    mfa_requests = get_mfa_requests(username, "ssh")
    for request in mfa_requests:
        if request["remote_ip"] == ip_address and (request["expires_at"] == None or request["expires_at"] > datetime.datetime.now()):
            ip_address_found = True
            if request["status"] == "approved":
                keys = get_user_ssh_keys(username)
                if keys == False:
                    return flask_response({"status": "ERROR", "detail": "SSH key retrieval failed"}, 500)
                return flask_response({"status": "OK", "result": "ACCEPT", "keys": make_serializable(keys)})

            if request["status"] == "rejected":
                return flask_response({"status": "OK", "result": "REJECT", "reason": "MFA rejected"})

    if not ip_address_found:
        try:
            cursor = g.db_conn.cursor()
            cursor.execute("INSERT INTO mfa_requests(created_at, updated_at, user_id, service, remote_ip) VALUES(NOW(), NOW(), %s, 'ssh', %s)", (user_id, ip_address))
            g.db_conn.commit()
        except Exception:
            sys.stderr.write(f"Failed storing mfa_request for {username} at {ip_address}:\n")
            sys.stderr.write(traceback.format_exc())
            return flask_response({"status": "ERROR", "detail": "Failed storing MFA request"}, 500)

    return flask_response({"status": "OK", "result": "PENDING", "reason": "MFA not approved"})

'''
Authenticate user SSH access without MFA
'''
@app.route(f"/v{API_VERSION}/ssh_auth_no_mfa/<username>", methods=["GET"])
def api_auth_ssh_access_no_mfa(username):
    keys = get_user_ssh_keys(username)
    if keys == False:
        return flask_response({"status": "ERROR", "detail": "SSH key retrieval failed"}, 500)

    is_service_account = False
    for regex in config["main"]["service_account_regex"]:
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

    return flask_response({"status": "OK", "keys": make_serializable(valid_keys)})


'''
Update users table
'''
@app.route(f"/v{API_VERSION}/maint/update_users", methods=["POST"])
def api_update_users():
    try:
        cursor = g.db_conn.cursor(dictionary=True)
        cursor.execute("SELECT username, display_name, email, deleted_at FROM users")
        db_users = cursor.fetchall()
    except Exception:
        sys.stderr.write("Failed getting users:\n")
        sys.stderr.write(traceback.format_exc())
        return flask_response({"status": "ERROR", "detail": "Failed getting users"}, 500)

    cursor = g.db_conn.cursor()

    if not init_ldap():
        return flask_response({"status": "ERROR", "detail": "Failed LDAP connection"}, 500)

    changes = 0

    for user_db in db_users:
        username = user_db["username"]
        user_ad = get_ldap_user(username)
        if user_db["deleted_at"] == None:
            if user_ad == {} or int(user_ad["userAccountControl"][0]) & 2 == 2:
                cursor.execute("UPDATE users SET deleted_at = NOW(), updated_at = NOW() WHERE username = %s", (username,))
                changes += 1
        else:
            if user_ad != {} and int(user_ad["userAccountControl"][0]) & 2 == 0:
                cursor.execute("UPDATE users SET deleted_at = NULL, updated_at = NOW() WHERE username = %s", (username,))
                changes += 1

        if user_ad != {} and format_name(user_ad).decode() != user_db["display_name"]:
            cursor.execute("UPDATE users SET updated_at = NOW(), display_name = %s WHERE username = %s", (format_name(user_ad), username))
            changes += 1

        if user_ad != {} and user_ad["mail"][0].decode() != user_db["email"]:
            cursor.execute("UPDATE users SET updated_at = NOW(), email = %s WHERE username = %s", (user_ad["mail"][0], username))
            changes += 1

    g.db_conn.commit()
    return flask_response({"status": "OK", "changes": changes})

'''
Handle 404s (though normally should get permissions error first)
'''
@app.errorhandler(404)
def api_not_found(e):
    return flask_response({"status": "ERROR", "detail": "Not found"}, 404)
