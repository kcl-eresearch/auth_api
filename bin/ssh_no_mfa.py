#!/usr/bin/python3
#
# Version of ssh.py which just returns all SSH keys for a user
# For use on "legacy" hosts without doing web MFA

import json
import os
import pwd
import requests
import sys
import syslog
import yaml

def log_error(message):
    syslog.syslog(syslog.LOG_ERR | syslog.LOG_AUTHPRIV, message)
    sys.stderr.write(f"{message}\n")

def log_info(message):
    syslog.syslog(syslog.LOG_INFO | syslog.LOG_AUTHPRIV, message)

def get_ssh_keys(username):
    url = f"https://{config['host']}/v{API_VERSION}/ssh_keys/{username}"
    try:
        r = requests.get(url, auth=(config["username"], config["password"]))
        if r.status_code == 200:
            try:
                response = r.json()
                if response["status"] == "OK":
                    log_info(f"Accepting authentication for {username}: {len(response['keys'])} keys")
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

if len(sys.argv) < 2:
    log_error("No user specified")
    sys.exit(1)

try:
    user = pwd.getpwnam(sys.argv[1])
except Exception as e:
    log_error("Invalid user specified")
    sys.exit(1)

# Drop root privileges no longer required
pwentry = pwd.getpwnam(config["run_as"])
os.setgid(pwentry.pw_gid)
os.setgroups([])
os.setuid(pwentry.pw_uid)

for key in get_ssh_keys(user.pw_name):
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
