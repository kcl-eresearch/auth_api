from cryptography.hazmat.backends import default_backend
from cryptography import x509
import datetime
import flask
import jinja2
import json
import ldap
import mysql.connector
import os
import re
import shutil
import smtplib
import socket
import sshpubkeys
import ssl
import subprocess
import sys
import tempfile
import uuid
import yaml

'''
Open config and connect to database
'''

def begin(config_dir="/etc/auth_api"):
    global cnx, config
    for file in ["main", "ca", "db", "ldap"]:
        config_file = f"{config_dir}/{file}.yaml"
        try:
            with open(config_file) as fh:
                config[file] = yaml.safe_load(fh)
        except Exception as e:
            sys.stderr.write(f"Failed loading {config_file}: {e}\n")
            return False

    try:
        cnx = mysql.connector.connect(host=config["db"]["host"], user=config["db"]["user"], password=config["db"]["password"], database=config["db"]["database"])
    except Exception as e:
        sys.stderr.write(f"Failed connecting to database: {e}\n")
        return False

    if "debug" in config["main"] and config["main"]["debug"]:
        with open("/tmp/auth_api_request_%s_%s_%s.debug" % (flask.request.method, flask.request.remote_addr, datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")), "wb") as fh:
            fh.write(flask.request.data)

    return True

'''
Initialise LDAP connection
'''
def init_ldap():
    global config, ldapc
    try:
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, config["ldap"]["ca_file"])
        ldapc = ldap.initialize(f"ldaps://{config['ldap']['host']}:636")
        ldapc.set_option(ldap.OPT_REFERRALS, 0)
        ldapc.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldapc.simple_bind_s(config["ldap"]["bind_dn"], config["ldap"]["bind_pw"])
    except Exception as e:
        sys.stderr.write(f"Failed connecting to LDAP: {e}\n")
        return False

    return True

'''
Get a user's details from LDAP
'''
def get_ldap_user(username):
    global ldapc
    result = ldapc.result(ldapc.search(config["ldap"]["base_dn"], ldap.SCOPE_SUBTREE, f"(&(objectClass=user)(sAMAccountName={username}))", ["mail", "givenName", "sn", "userAccountControl"]))
    if result[1] == []:
        return {}

    if "mail" not in result[1][0][1]:
        result[1][0][1]["mail"] = [f"{username}@kcl.ac.uk"]

    return result[1][0][1]

'''
Retrieve sane display name from user LDAP entry
'''
def format_name(user_entry):
    return (user_entry["givenName"][0] + b" " + user_entry["sn"][0]).strip(b" -")

'''
Get ID from database of relevant user - creating new entry if required
'''
def get_user_id(username):
    global cnx
    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT id, deleted_at FROM users WHERE username = %s", (username,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Querying database for user failed: {e}\n")
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
    except Exception as e:
        sys.stderr.write(f"Querying LDAP for user failed: {e}\n")
        return False

    if ldap_user == {}:
        return 0

    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("INSERT INTO users(username, display_name, email, created_at) VALUES(%s, %s, %s, NOW())", (username, format_name(ldap_user), ldap_user["mail"][0]))
        cnx.commit()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Adding new user to database failed: {e}\n")
        return False

    if len(result) == 1:
        return result[0]["id"]

    sys.stderr.write("Could not find new user in database\n")
    return False

'''
Get a user's SSH keys
'''
def get_user_ssh_keys(username):
    global cnx
    user_id = get_user_id(username)
    if not user_id:
        return False

    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT created_at, name, type, pub_key FROM ssh_keys WHERE user_id = %s", (user_id,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Error getting ssh keys for {username}: {e}\n")
        return False

    return result

'''
Get a user's VPN certs from database
'''
def get_user_vpn_keys(username):
    global cnx
    user_id = get_user_id(username)
    if not user_id:
        return False

    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT created_at, expires_at, uuid, name, public_cert, status FROM vpn_keys WHERE user_id = %s", (user_id,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Error getting VPN certs for {username}: {e}\n")
        return False

    return result

'''
Encode response as JSON and return it via Flask
'''
def flask_response(data, code=200):
    resp = flask.Response(json.dumps(data), status=code, content_type='application/json')
    return resp

'''
Make list of dicts serializable - convert datetimes to unix timestamps
'''
def make_serializable(data):
    output = []
    for datum in data:
        my_output = {}
        for k, v in datum.items():
            if isinstance(v, datetime.datetime):
                my_output[k] = int(v.timestamp())
            else:
                my_output[k] = v
        output.append(my_output)
    return output

'''
Validate SSH public key
'''
def validate_ssh_key(type, pub_key, name):
    ssh_key = sshpubkeys.SSHKey(f"{type} {pub_key} {name}")
    try:
        ssh_key.parse()
    except Exception as e:
        return False
    return True

'''
Revoke a VPN key
'''
def revoke_vpn_key(username, key_name):
    user_id = get_user_id(username)
    if not user_id:
        return False

    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT id, public_cert FROM vpn_keys WHERE status = 'active' AND user_id = %s AND name = %s", (user_id, key_name))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Failed getting data for user {username} certificate {key_name}: {e}\n")
        return False

    try:
        for certificate in result:
            cursor.execute("UPDATE vpn_keys SET status = 'revoked' WHERE id = %s", (certificate["id"],))
            cert_data = x509.load_pem_x509_certificate(certificate["public_cert"].encode("utf8"), default_backend())
            serial_number = str(cert_data.serial_number)
            token = subprocess.check_output([config["ca"]["exe"], "ca", "token", "--provisioner", config["ca"]["provisioner"], "--password-file", "/etc/auth_api/ca_password.txt", "--ca-url", config["ca"]["url"], "--root", config["ca"]["root_crt"], "--revoke", serial_number], stderr=subprocess.DEVNULL).strip()
            revoke = subprocess.check_output([config["ca"]["exe"], "ca", "revoke", serial_number, "--token", token], stderr=subprocess.DEVNULL)
        cnx.commit()
    except Exception as e:
        sys.stderr.write(f"Failed setting revocation status in database for user {username} certificate {key_name}: {e}\n")
        return False

    return True

'''
Get user MFA requests from database
'''
def get_mfa_requests(username, service="all"):
    user_id = get_user_id(username)
    if not user_id:
        return False

    requests = []
    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT created_at, updated_at, expires_at, service, remote_ip, status FROM mfa_requests WHERE user_id = %s AND (expires_at IS NULL OR expires_at > NOW())", (user_id,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Failed getting {service} MFA requests for {username}: {e}")
        return False

    for request in result:
        if service == "all" or service == request["service"]:
            requests.append(request)

    return requests

'''
Authenticate request based on path, method and user
'''
def auth_request(path, method, user):
    global config

    # Deny anonymous access
    if user in ["", None]:
        sys.stderr.write("Access denied: empty username\n")
        return False

    # Allow anyone to access status page
    if path == "/":
        return True

    # Deny users not in config file
    if user not in [config["main"]["auth_user_web"], config["main"]["auth_user_bastion"], config["main"]["auth_user_maint"]]:
        sys.stderr.write("Access denied: username not authorised\n")
        return False

    # Handle bogus paths
    m = re.match(r'^/v[0-9]+/([a-z_]+)/[a-z0-9_]+(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?', path)
    if not m:
        sys.stderr.write("Access denied: invalid API path\n")
        return False

    req_function = m.group(1)

    permissions = {
        config["main"]["auth_user_web"]: [
            ("ssh_keys", "GET"),
            ("ssh_keys", "PUT"),
            ("vpn_keys", "GET"),
            ("vpn_keys", "POST"),
            ("vpn_keys", "DELETE"),
            ("mfa_requests", "GET"),
            ("mfa_requests", "POST")
        ],
        config["main"]["auth_user_bastion"]: [
            ("ssh_auth", "GET"),
            ("vpn_auth", "GET")
        ],
        config["main"]["auth_user_maint"]: [
            ("maint", "POST")
        ]
    }

    if (req_function, method) in permissions[user]:
        return True

    sys.stderr.write("Access denied: no valid permissions\n")

'''
Send email notification to user notifying of key changes
'''
def send_email(username, service):
    try:
        with open("/etc/auth_api/smtp.yaml") as fh:
            smtp_config = yaml.safe_load(fh)
    except Exception as e:
        sys.stderr.write(f"Failed loading SMTP configuration: {e}\n")
        return False

    try:
        with open("/etc/auth_api/mail_template.j2") as fh:
            mail_template = jinja2.Template(fh.read())
    except Exception as e:
        sys.stderr.write(f"Failed loading mail template: {e}\n")
        return False

    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT display_name, email FROM users WHERE username = %s", (username,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write("fFailed retrieving user details from database: {e}\n")
        return False

    if len(result) < 1:
        sys.stderr.write(f"Did not find user {username} in database\n")
        return False

    if result[0]["display_name"] == "":
        result[0]["display_name"] = username

    if result[0]["email"] == "":
        sys.stderr.write(f"Did not find email address for {username} in database\n")
        return False

    try:
        mail_message = mail_template.render(
            from_name=smtp_config["from_name"],
            from_addr=smtp_config["from_addr"],
            display_name=result[0]["display_name"],
            user_email=result[0]["email"],
            service_name=service.upper(),
            username=username
        )
    except Exception as e:
        sys.stderr.write(f"Failed rendering mail message: {e}\n")
        return False

    try:
        smtp = smtplib.SMTP(smtp_config["server"], smtp_config["port"])
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(smtp_config["username"], smtp_config["password"])
        smtp.sendmail(smtp_config["from_addr"], result[0]["email"], mail_message)
        smtp.quit()
    except Exception as e:
        sys.stderr.write(f"Failed sending mail message: {e}\n")
        return False

    return True

'''
End of functions library
'''

# Must be integer
API_VERSION = 1

config = {}
cnx = None
ldapc = None

app = flask.Flask(__name__)

'''
Flask URI routing
'''

'''
Initalise and authenticate
'''
@app.before_request
def api_before_request():
    if not begin():
        return flask_response({"status": "ERROR", "detail": "API initialisation failed"}, 500)

    if not auth_request(flask.request.path, flask.request.method, flask.request.remote_user):
        return flask_response({"status": "ERROR", "detail": "Forbidden"}, 403)


'''
Status if nothing requested - also used for monitoring
'''
@app.route('/')
def api_status():
    table_counts = {}
    for table in ['users', 'mfa_requests', 'ssh_keys', 'vpn_keys']:
        try:
            cursor = cnx.cursor(dictionary=True)
            cursor.execute(f"SELECT COUNT(*) AS table_count FROM {table}")
            result = cursor.fetchall()
        except Exception as e:
            sys.stderr.write(f"Error getting status (count of {table} table): {e}\n")
            return flask_response({"status": "ERROR", "detail": f"Failed getting {table} count: {e}"}, 500)

        table_counts[table] = result[0]["table_count"]

    return flask_response({"status": "OK", "table_counts": table_counts, "host": socket.getfqdn(), "version": API_VERSION})

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
    except Exception as e:
        sys.stderr.write(f"Failed loading VPN config template: {e}\n")
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500)

    try:
        with open(config["ca"]["root_crt"]) as fh:
            ca_cert = fh.read()
    except Exception as e:
        sys.stderr.write(f"Failed loading CA cert: {e}\n")
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500)

    try:
        output = subprocess.check_output([config["ca"]["exe"], "ca", "certificate", "--provisioner", config["ca"]["provisioner"], "--provisioner-password-file", "/etc/auth_api/ca_password.txt", "--ca-url", config["ca"]["url"], "--root", config["ca"]["root_crt"], "--not-after", "%dh" % (24 * config["ca"]["cert_lifetime"]), cert_uuid, path_crt, path_key], stderr=subprocess.STDOUT)
    except Exception as e:
        sys.stderr.write(f"Failed generating VPN key/certificate: {e}\n")
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate generation failed"}, 500)

    try:
        with open(path_crt) as fh:
            data_crt = line = ""
            while line != "-----END CERTIFICATE-----\n":
                line = fh.readline()
                data_crt += line

        with open(path_key) as fh:
            data_key = fh.read()
    except Exception as e:
        sys.stderr.write(f"Failed reading new VPN key/certificate: {e}\n")
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate read failed"}, 500)

    try:
        cert = x509.load_pem_x509_certificate(data_crt.encode('utf8'), default_backend())
    except Exception as e:
        sys.stderr.write(f"Failed decoding new certificate: {e}\n")
        return flask_response({"status": "ERROR", "detail": "VPN key/certificate decode failed"}, 500)

    if not revoke_vpn_key(username, key_name):
        return flask_response({"status": "ERROR", "detail": "Old VPN key/certificate revocation failed"}, 500)

    try:
        cursor = cnx.cursor()
        cursor.execute("INSERT INTO vpn_keys(created_at, expires_at, user_id, uuid, name, public_cert, status) VALUES(%s, %s, %s, %s, %s, %s, 'active')", (cert.not_valid_before, cert.not_valid_after, user_id, cert_uuid, key_name, data_crt))
        cnx.commit()
    except Exception as e:
        sys.stderr.write(f"Failed storing certificate in database: {e}\n")
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

    queries = []

    try:
        cursor = cnx.cursor()
        for name, key in ssh_keys.items():
            if name == "" or not isinstance(name, str):
                return flask_response({"status": "ERROR", "detail": "Invalid key name"}, 400)

            if "type" not in key or key["type"] not in config["main"]["ssh_key_types"]:
                return flask_response({"status": "ERROR", "detail": "Invalid key type"}, 400)

            if "pub_key" not in key:
                return flask_response({"status": "ERROR", "detail": "Invalid key data"}, 400)

            if not validate_ssh_key(key["type"], key["pub_key"], name):
                return flask_response({"status": "ERROR", "detail": "Invalid key data"}, 400)

            if name not in existing_named or existing_named[name]["type"] != key["type"] or existing_named[name]["pub_key"] != key["pub_key"]:
                cursor.execute("DELETE FROM ssh_keys WHERE user_id = %s AND name = %s", (user_id, name))
                cursor.execute("INSERT INTO ssh_keys(created_at, user_id, type, name, pub_key) VALUES(NOW(), %s, %s, %s, %s)", (user_id, key["type"], name, key["pub_key"]))

        for name, data in existing_named.items():
            if name not in ssh_keys:
                cursor.execute("DELETE FROM ssh_keys WHERE user_id = %s AND name = %s", (user_id, name))

        cnx.commit()

    except Exception as e:
        sys.stderr.write(f"Failed saving SSH keys: {e}\n")
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
        cursor = cnx.cursor()
        cursor.execute("UPDATE mfa_requests SET status = %s, updated_at = NOW(), expires_at = %s WHERE user_id = %s AND service = %s AND remote_ip = %s AND (expires_at IS NULL OR expires_at > NOW())", (mfa_request["status"], datetime.datetime.now() + datetime.timedelta(minutes=config["main"]["mfa_timeoutfine"][mfa_request["status"]]), user_id, mfa_request["service"], mfa_request["ip_address"]))
        cnx.commit()
    except Exception as e:
        sys.stderr.write(f"Failed updating MFA request for {username}: {e}\n")
        return flask_response({"status": "ERROR", "detail": "Failed saving MFA request"}, 500)

    return api_get_mfa_requests(username)

'''
Authenticate user VPN access
'''
@app.route(f"/v{API_VERSION}/vpn_auth/<username>/<ip_address>/<cert_cn>", methods=["GET"])
def api_auth_vpn_access(username, ip_address, cert_cn):
    user_id = get_user_id(username)
    if not user_id:
        return flask_response({"status": "ERROR", "detail": "User not found"}, 404)

    key_valid = False
    vpn_keys = get_user_vpn_keys(username)
    for key in vpn_keys:
        if key["status"] == "active" and key["uuid"] == cert_cn and key["expires_at"] > datetime.datetime.now():
            key_valid = True
            break

    if not key_valid:
        return flask_response({"status": "OK", "result": "REJECT", "reason": "invalid certificate"})

    ip_address_found = False
    mfa_requests = get_mfa_requests(username, "vpn")
    for request in mfa_requests:
        if request["remote_ip"] == ip_address:
            ip_address_found = True
            if request["status"] == "approved" and status["expires_at"] > datetime.datetime.now():
                return flask_response({"status": "OK", "result": "ACCEPT"})

            if request["status"] == "rejected":
                return flask_response({"status": "OK", "result": "REJECT", "reason": "MFA rejected"})

    if not ip_address_found:
        try:
            cursor = cnx.cursor()
            cursor.execute("INSERT INTO mfa_requests(created_at, updated_at, user_id, service, remote_ip) VALUES(NOW(), NOW(), %s, 'vpn', %s)", (user_id, ip_address))
            cnx.commit()
        except Exception as e:
            sys.stderr.write(f"Failed storing mfa_request for {username} at {ip_address}: {e}\n")
            return flask_response({"status": "ERROR", "detail": "Failed storing MFA request"}, 500)

    return flask_response({"status": "OK", "result": "PENDING", "reason": "MFA not approved"})

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
        if request["remote_ip"] == ip_address:
            ip_address_found = True
            if request["status"] == "approved" and request["expires_at"] > datetime.datetime.now():
                keys = get_user_ssh_keys(username)
                if keys == False:
                    return flask_response({"status": "ERROR", "detail": "SSH key retrieval failed"}, 500)
                return flask_response({"status": "OK", "result": "ACCEPT", "keys": make_serializable(keys)})

            if request["status"] == "rejected":
                return flask_response({"status": "OK", "result": "REJECT", "reason": "MFA rejected"})

    if not ip_address_found:
        try:
            cursor = cnx.cursor()
            cursor.execute("INSERT INTO mfa_requests(created_at, updated_at, user_id, service, remote_ip) VALUES(NOW(), NOW(), %s, 'ssh', %s)", (user_id, ip_address))
            cnx.commit()
        except Exception as e:
            sys.stderr.write(f"Failed storing mfa_request for {username} at {ip_address}: {e}\n")
            return flask_response({"status": "ERROR", "detail": "Failed storing MFA request"}, 500)

    return flask_response({"status": "OK", "result": "PENDING", "reason": "MFA not approved"})

'''
Update users table
'''
@app.route(f"/v{API_VERSION}/maint/update_users", methods=["POST"])
def api_update_users():
    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT username, display_name, email, deleted_at FROM users")
        db_users = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Failed getting users: {e}\n")
        return flask_response({"status": "ERROR", "detail": "Failed getting users"}, 500)

    cursor = cnx.cursor()

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

    cnx.commit()
    return flask_response({"status": "OK", "changes": changes})

'''
Handle 404s (though normally should get permissions error first)
'''
@app.errorhandler(404)
def api_not_found(e):
    return flask_response({"status": "ERROR", "detail": "Not found"}, 404)
