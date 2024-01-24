import click
import json
import os
import psutil
import pwd
import requests
import socket
import subprocess
import sys
import time
import yaml

from flask import Blueprint, current_app
from auth_api.common import log_error, log_info, get_ssh_keys, get_config

bp = Blueprint('ssh', __name__)

def get_ssh_auth(username, remote_ip):
    config = get_config("/etc/auth_api.yaml")
    url = f"https://{config['host']}/v1/ssh_auth/{username}/{remote_ip}"
    timeout = time.time() + config["timeout"]
    ppid = os.getppid()
    log_info(
        "Processing auth request: %s"
        % json.dumps(
            {
                "username": username,
                "remote_ip": remote_ip,
                "pid": os.getpid(),
                "ppid": ppid,
            }
        )
    )
    while time.time() < timeout:
        try:
            r = requests.get(url, auth=(config["username"], config["password"]))
            if r.status_code == 200:
                try:
                    response = r.json()
                    if response["status"] == "OK":
                        if response["result"] == "ACCEPT":
                            log_info(
                                f"Accepting authentication for {username} from {remote_ip}: {len(response['keys'])} keys"
                            )
                            return response["keys"]

                        if response["result"] == "REJECT":
                            log_info(
                                f"Rejecting authentication for {username} from {remote_ip}: {response['reason']}"
                            )
                            return []

                        if response["result"] == "PENDING":
                            pass
                        else:
                            log_error(f"Unexpected result from {url}: {e}")
                except Exception as e:
                    log_error(f"Failed decoding response from {url}: {e}")
                    log_error("Response was:")
                    log_error(r.text)
            else:
                log_error(f"Unexpected HTTP status fetching {url}: {r.status_code}")
        except Exception as e:
            log_error(f"Failed fetching {url}: {e}")

        time.sleep(2)

    log_info(f"Rejecting authentication for {username} from {remote_ip}: timeout")
    return []

def get_ssh_keys(username, subcmd = "ssh_keys"):
    config = get_config("/etc/auth_api.yaml")
    url = f"https://{config['host']}/v1/{subcmd}/{username}"
    try:
        r = requests.get(url, auth=(config["username"], config["password"]))
        if r.status_code == 200:
            try:
                response = r.json()
                if response["status"] == "OK":
                    log_info(
                        f"Accepting authentication for {username}: {len(response['keys'])} keys"
                    )
                    return response["keys"]

                log_error(f"Unexpected status from {url}: {response['status']}")
                return []
            except Exception as e:
                log_error(f"Failed decoding response from {url}: {e}")
                log_error("Response was:")
                log_error(r.text)
        else:
            log_error(f"Unexpected HTTP status fetching {url}: {r.status_code}")
            return []
    except Exception as e:
        log_error(f"Failed fetching {url}: {e}")
        return []

@bp.cli.command('ssh')
@click.argument('username')
def ssh(username):
    CMD_RSYNC = "/usr/bin/rrsync /"
    CMD_SFTP = "internal-sftp"
    CMD_BOGUS = "/usr/sbin/nologin"

    config = get_config("/etc/auth_api.yaml")

    ppid = os.getppid()
    p_sshd = psutil.Process(ppid)
    if p_sshd.exe() != "/usr/sbin/sshd":
        log_error("Parent process is not sshd")
        sys.exit(1)

    if len(sys.argv) < 2:
        log_error("No user specified")
        sys.exit(1)

    try:
        user = pwd.getpwnam(username)
    except Exception as e:
        log_error("Invalid user specified")
        sys.exit(1)

    remote_ip = None
    for conn in psutil.net_connections(kind="tcp"):
        if conn.laddr[1] == 22 and conn.status == psutil.CONN_ESTABLISHED:
            proc = psutil.Process(conn.pid)
            if proc.ppid() == ppid and proc.username() == "sshd":
                remote_ip = conn.raddr[0]
                break

    if not remote_ip:
        log_error("Cannot determine remote IP address")
        sys.exit(1)

    # Drop root privileges no longer required
    pwentry = pwd.getpwnam(config["run_as"])
    os.setgid(pwentry.pw_gid)
    os.setgroups([])
    os.setuid(pwentry.pw_uid)

    for key in get_ssh_auth(user.pw_name, remote_ip):
        restrictions = []
        if key["allowed_ips"]:
            try:
                allowed_ips = ",".join(json.loads(key["allowed_ips"]))
            except:  # Play it safe and don't allow key if invalid allowed_ips
                continue
            restrictions.append('from="%s"' % allowed_ips)

        if key["access_type"] != "any":
            restrictions.append("restrict")

            if key["access_type"] == "rsync":
                command = CMD_RSYNC
            elif key["access_type"] == "sftp":
                command = CMD_SFTP
            else:
                command = CMD_BOGUS

            restrictions.append('command="%s"' % command)

        print((" ".join([",".join(restrictions), key["type"], key["pub_key"]])).strip())

    sys.stdout.flush()

@bp.cli.command('ssh_get_keys_yaml')
@click.argument('username')
def ssh_get_keys_yaml(username):
    config = get_config("/etc/auth_api.yaml")

    if len(sys.argv) < 2:
        log_error("No user specified")
        sys.exit(1)

    # Drop root privileges no longer required
    pwentry = pwd.getpwnam(config["run_as"])
    os.setgid(pwentry.pw_gid)
    os.setgroups([])
    os.setuid(pwentry.pw_uid)

    keys = []
    for key in get_ssh_keys(username):
        keys.append(key)

    print(yaml.dump(keys))
    sys.stdout.flush()

def no_mfa_subcmd(username, scriptname):
    config = get_config("/etc/auth_api.yaml")

    CMD_MAP = {
        "rsync": "/usr/bin/rrsync /",
        "rsync_ro": "/usr/bin/rrsync -ro /",
        "sftp": "internal-sftp",
        "sftp_ro": "internal-sftp -R",
    }
    CMD_BOGUS = "/usr/sbin/nologin"

    try:
        user = pwd.getpwnam(username)
    except Exception as e:
        log_error("Invalid user specified")
        sys.exit(1)

    # Drop root privileges no longer required
    pwentry = pwd.getpwnam(config["run_as"])
    os.setgid(pwentry.pw_gid)
    os.setgroups([])
    os.setuid(pwentry.pw_uid)

    for key in get_ssh_keys(user.pw_name, "ssh_auth_no_mfa"):
        if scriptname == "ssh_tre_sftp" and key["access_type"] != "sftp":
            continue

        if scriptname == "ssh_ro_sftp" and key["access_type"] != "sftp_ro":
            continue

        restrictions = []
        if key["allowed_ips"]:
            try:
                allowed_ips = ",".join(json.loads(key["allowed_ips"]))
            except:  # Play it safe and don't allow key if invalid allowed_ips
                continue
            restrictions.append('from="%s"' % allowed_ips)
        else:
            if scriptname == "ssh_tre_sftp":
                continue

        command = None
        if key["access_type"] != "any":
            restrictions.append("restrict")

            if key["access_type"] in CMD_MAP:
                command = CMD_MAP[key["access_type"]]
            else:
                command = CMD_BOGUS

            restrictions.append('command="%s"' % command)

        print((" ".join([",".join(restrictions), key["type"], key["pub_key"]])).strip())

    sys.stdout.flush()


@bp.cli.command('ssh_no_mfa')
@click.argument('username')
def ssh_no_mfa(username):
    no_mfa_subcmd(username, "ssh_no_mfa")

@bp.cli.command('ssh_tre_sftp')
@click.argument('username')
def ssh_tre_sftp(username):
    no_mfa_subcmd(username, "ssh_tre_sftp")

@bp.cli.command('ssh_ro_sftp')
@click.argument('username')
def ssh_ro_sftp(username):
    no_mfa_subcmd(username, "ssh_ro_sftp")

@bp.cli.command('ssh_service_accounts')
@click.argument('username')
def ssh_service_accounts(username):
    config = get_config("/etc/auth_api.yaml")

    try:
        user = pwd.getpwnam(username)
    except Exception as e:
        log_error("Invalid user specified")
        sys.exit(1)

    if (
        "service_account_restrict_users" in config
        and user.pw_name in config["service_account_restrict_users"]
    ):
        ip_allowed = config["service_account_restrict_users"][user.pw_name]
    elif "service_account_restrict" in config:
        ip_allowed = config["service_account_restrict"]
    else:
        ip_allowed = ["127.0.0.0/8"]

    ip_allowed_csv = ",".join(ip_allowed)

    # Drop root privileges no longer required
    pwentry = pwd.getpwnam(config["run_as"])
    os.setgid(pwentry.pw_gid)
    os.setgroups([])
    os.setuid(pwentry.pw_uid)

    for key in get_ssh_keys(user.pw_name):
        print(f"from=\"{ip_allowed_csv}\" {key['type']} {key['pub_key']}")

    sys.stdout.flush()

@bp.cli.command('ssh_slurm')
@click.argument('username')
def ssh_slurm(username):
    try:
        user = pwd.getpwnam(username)
    except Exception as e:
        log_error("Invalid user specified")
        sys.exit(1)

    try:
        result = subprocess.run(
            [
                "/usr/bin/squeue",
                "-t",
                "running",
                "-u",
                user.pw_name,
                "-w",
                socket.gethostname().split(".")[0],
                "-h",
                "-o",
                "%u",
            ],
            capture_output=True,
            check=True,
        )
    except Exception as e:
        log_error(f"Failed getting user slurm jobs: {e}")
        sys.exit(1)

    if len(result.stdout.decode().splitlines()) == 0:
        log_info(f"Denying authentication for {user.pw_name}: no jobs running here")
        sys.exit(1)

    for key in get_ssh_keys(user.pw_name):
        print(f"{key['type']} {key['pub_key']}")

    sys.stdout.flush()
