import datetime
from flask import Blueprint, render_template, request, redirect
from auth_api.common import get_db
from auth_api.user import *

dashboard = Blueprint("dashboard", __name__)

@dashboard.before_request
def dashboard_before_request():
    if not request.remote_user:
        request.environ['REMOTE_USER'] = 'testuser'
        #return render_template('access_denied.html'), 403

@dashboard.route(f"/", methods=["GET"])
def home():
    return render_template('index.html')

@dashboard.route(f"/mfa", methods=["GET"])
def mfa():
    # Load MFA requests.
    user_id = get_user_id(request.remote_user)
    mfa_requests = get_mfa_requests(request.remote_user)
    if not mfa_requests:
        mfa_requests = []
    return render_template('mfa.html', mfa_requests=mfa_requests, user_id=user_id)

@dashboard.route(f"/mfa/<int:request_id>", methods=["POST"])
def mfa_set(request_id):
    config = current_app.config['authapi']
    user_id = get_user_id(request.remote_user)

    # Load MFA requests.
    action = request.form.get("action")
    db = get_db()
    try:
        with db.cursor() as cursor:
            cursor.execute(
                "UPDATE mfa_requests SET status = %s, updated_at = NOW(), expires_at = %s WHERE id = %s AND user_id = %s AND (expires_at IS NULL OR expires_at > NOW())",
                (
                    action,
                    datetime.datetime.now()
                    + datetime.timedelta(
                        minutes=config["mfa_timeout"][action]
                    ),
                    request_id,
                    user_id,
                ),
            )
        db.commit()
    except Exception:
        raise Exception(f"Failed updating MFA request for {request.remote_user}:\n")
    return redirect("/mfa")

@dashboard.route(f"/ssh", methods=["GET"])
def ssh():
    ssh_keys = get_user_ssh_keys(request.remote_user)
    return render_template('ssh.html', ssh_keys=ssh_keys)

@dashboard.route(f"/ssh/<int:key_id>", methods=["POST"])
def ssh_set(key_id):
    user_id = get_user_id(request.remote_user)

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "DELETE FROM ssh_keys WHERE id = %s AND user_id = %s",
            (
                key_id,
                user_id,
            ),
        )
    db.commit()

    return redirect("/ssh")

@dashboard.route(f"/ssh/new", methods=["POST"])
def ssh_add():
    ssh_key = request.form.get("ssh_key")
    ssh_key_parts = ssh_key.split(" ")

    user_id = get_user_id(request.remote_user)

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO ssh_keys(created_at, user_id, type, pub_key, name) VALUES(NOW(), %s, %s, %s, %s)",
            (
                user_id,
                ssh_key_parts[0],
                ssh_key_parts[1],
                ssh_key_parts[2],
            ),
        )
    db.commit()

    return redirect("/ssh")

@dashboard.route(f"/vpn", methods=["GET"])
def vpn():
    return render_template('vpn.html')
