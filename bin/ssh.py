#!/usr/bin/python3

import json
import os
import pwd
import psutil
import requests
import sys
import syslog
import time
import yaml

def log_error(message):
    syslog.syslog(syslog.LOG_ERR | syslog.LOG_AUTHPRIV, message)
    sys.stderr.write(f"{message}\n")

def log_info(message):
    syslog.syslog(syslog.LOG_INFO | syslog.LOG_AUTHPRIV, message)

def get_ssh_keys(username, remote_ip):
    url = f"https://{config['host']}/v{API_VERSION}/ssh_auth/{username}/{remote_ip}"
    timeout = time.time() + config["timeout"]
    log_info("Processing auth request: %s" % json.dumps({"username": username, "remote_ip": remote_ip, "pid": os.getpid(), "ppid": ppid}))
    while time.time() < timeout:
        try:
            r = requests.get(url, auth=(config["username"], config["password"]))
            if r.status_code == 200:
                try:
                    response = r.json()
                    if response["status"] == "OK":
                        if response["result"] == "ACCEPT":
                            log_info(f"Accepting authentication for {username} from {remote_ip}: {len(response['keys'])} keys")
                            return response["keys"]

                        if response["result"] == "REJECT":
                            log_info(f"Rejecting authentication for {username} from {remote_ip}: {response['reason']}")
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

API_VERSION = 1
CMD_RSYNC = "/usr/bin/rrsync /"
CMD_SFTP="internal-sftp"
CMD_BOGUS="/usr/sbin/nologin"

try:
    with open("/etc/auth_api.yaml") as fh:
        config = yaml.safe_load(fh)
except Exception as e:
    log_error(f"Failed loading config: {e}")
    sys.exit(1)

ppid = os.getppid()
p_sshd = psutil.Process(ppid)
if p_sshd.exe() != "/usr/sbin/sshd":
    log_error("Parent process is not sshd")
    sys.exit(1)

if len(sys.argv) < 2:
    log_error("No user specified")
    sys.exit(1)

try:
    user = pwd.getpwnam(sys.argv[1])
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

for key in get_ssh_keys(user.pw_name, remote_ip):
    restrictions = []
    if key["allowed_ips"]:
        try:
            allowed_ips = ",".join(json.loads(key["allowed_ips"]))
        except: # Play it safe and don't allow key if invalid allowed_ips
            continue
        restrictions.append("from=\"%s\"" % allowed_ips)

    if key["access_type"] != "any":
        restrictions.append("restrict")

        if key["access_type"] == "rsync":
            command = CMD_RSYNC
        elif key["access_type"] == "sftp":
            command = CMD_SFTP
        else:
            command = CMD_BOGUS

        restrictions.append("command=\"%s\"" % command)

    print((" ".join([",".join(restrictions), key["type"], key["pub_key"]])).strip())

sys.stdout.flush()
