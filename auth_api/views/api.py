import json
import socket
import sys
import re
import traceback
from auth_api import API_VERSION
from flask import Blueprint, current_app, Response, request
from flaskext.mysql import MySQL

api_v1 = Blueprint("apiv1", __name__, url_prefix="/api/v1")


'''
Authenticate request based on path, method and user
'''
def auth_request(path, method, user):
    # Deny anonymous access
    if user in ["", None]:
        sys.stderr.write("Access denied: empty username\n")
        return False

    # Allow anyone to access status page
    if path == "/":
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
    m = re.match(r'^/v[0-9]+/([a-z_]+)(/[a-z0-9_]+(/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?)?', path)
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
            ("mfa_requests", "POST")
        ],
        current_app.config["authapi"]["auth_user_bastion"]: [
            ("ssh_auth", "GET"),
            ("ssh_auth_no_mfa", "GET"),
            ("ssh_keys", "GET"),
            ("vpn_auth", "GET")
        ],
        current_app.config["authapi"]["auth_user_maint"]: [
            ("maint", "POST")
        ],
        current_app.config["authapi"]["auth_user_admin"]: [
            ("ssh_keys", "GET"),
            ("vpn_keys", "GET"),
            ("mfa_requests", "GET")
        ],
    }

    if (req_function, method) in permissions[user]:
        return True

    sys.stderr.write("Access denied: no valid permissions\n")

'''
Encode response as JSON and return it via Flask
'''
def api_response(data, code=200):
    resp = Response(json.dumps(data), status=code, content_type='application/json')
    return resp

'''
Initalise and authenticate
'''
@api_v1.before_request
def apiv1_before_request():
    if not auth_request(request.path, request.method, request.remote_user):
        return api_response({"status": "ERROR", "detail": "Forbidden"}, 403)

'''
Status if nothing requested - also used for monitoring
'''
@api_v1.route('/')
def api_status():
    mysql = MySQL()
    mysql.init_app(current_app)
    db = mysql.get_db()

    table_counts = {}
    for table in ['users', 'mfa_requests', 'ssh_keys', 'vpn_keys']:
        try:
            with db.cursor(dictionary=True) as cursor:
                cursor.execute(f"SELECT COUNT(*) AS table_count FROM {table}")
                result = cursor.fetchall()
        except Exception as e:
            sys.stderr.write(f"Error getting status (count of {table} table):\n")
            sys.stderr.write(traceback.format_exc())
            return api_response({"status": "ERROR", "detail": f"Failed getting {table} count: {e}"}, 500)

        table_counts[table] = result[0]["table_count"]

    return api_response({"status": "OK", "table_counts": table_counts, "host": socket.getfqdn(), "version": API_VERSION})
