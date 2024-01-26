
from flask import Blueprint, render_template, request
from auth_api.user import *

dashboard = Blueprint("dashboard", __name__)

@dashboard.before_request
def dashboard_before_request():
    if not request.remote_user:
        #request.environ['REMOTE_USER'] = 'testuser'
        return render_template('access_denied.html'), 403

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


@dashboard.route(f"/ssh", methods=["GET"])
def ssh():
    return render_template('ssh.html')


@dashboard.route(f"/vpn", methods=["GET"])
def vpn():
    return render_template('vpn.html')
