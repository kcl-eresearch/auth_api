#!/usr/bin/python3
#
# Version of ssh.py which is for service accounts
# These don't use MFA but are IP address restricted

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

if "service_account_restrict_users" in config and user.pw_name in config["service_account_restrict_users"]:
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
