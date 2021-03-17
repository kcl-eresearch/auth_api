import flask
import json
import ldap
import mysql.connector
import os
import re
import socket
import sys
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
    result = ldapc.result(ldapc.search(config["ldap"]["base_dn"], ldap.SCOPE_SUBTREE, f"(&(objectClass=user)({config['ldap']['attr_username']}={username}))", [config["ldap"]["attr_email"], config["ldap"]["attr_display_name"]]))
    if len(result) != 2:
        return {}

    return result[1][0][1]

'''
Get ID from database of relevant user - creating new entry if required
'''
def get_user_id(username):
    global cnx
    try:
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Querying database for user failed: {e}\n")
        return False

    if len(result) == 1:
        return result[0]["id"]

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
        cursor.execute("INSERT INTO users(username, display_name, email) VALUES(%s, %s, %s)", (username, ldap_user["displayName"][0], ldap_user["mail"][0]))
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
        cursor.execute("SELECT type, pub_key FROM ssh_keys WHERE user_id = %s", (user_id,))
        result = cursor.fetchall()
    except Exception as e:
        sys.stderr.write(f"Error getting ssh keys for {username}: {e}\n")
        return False

    return result

'''
Set a user's SSH keys
'''
def set_user_ssh_keys(username, ssh_keys):
    existing = get_user_ssh_keys(username)
    if not existing:
        return False

'''
Encode response as JSON and return it via Flask
'''
def flask_response(data, code=200):
    resp = flask.Response(json.dumps(data), status=code, content_type='application/json')
    return resp

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
    if user not in [config["main"]["auth_user_web"], config["main"]["auth_user_bastion"]]:
        sys.stderr.write("Access denied: username not authorised\n")
        return False

    # Handle bogus paths
    m = re.match(r'^/v[0-9]+/([a-z_]+)/[a-z0-9]+(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?', path)
    if not m:
        sys.stderr.write("Access denied: invalid API path\n")
        return False

    req_function = m.group(1)

    permissions = {
        config["main"]["auth_user_web"]: [
            ("ssh_keys", "GET"),
            ("ssh_keys", "POST"),
            ("vpn_keys", "GET"),
            ("vpn_keys", "POST"),
            ("auth_attempts", "GET"),
            ("auth_attempts", "POST")
        ],
        config["main"]["auth_user_bastion"]: [
            ("ssh_approved", "GET"),
            ("vpn_approved", "GET")
        ]
    }

    if (req_function, method) in permissions[user]:
        return True

    sys.stderr.write("Access denied: no valid permissions\n")

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
    for table in ['users', 'mfa_requests', 'ssh_keys', 'vpn_certs']:
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
    if not keys:
        return flask_response({"status": "ERROR", "detail": "Key retrieval failed"}, 500)

    return flask_response({"status": "OK", "keys": keys})

'''
Handle 404s (though normally should get permissions error first)
'''
@app.errorhandler(404)
def api_not_found(e):
    return flask_response({"status": "ERROR", "detail": "Not found"}, 404)
