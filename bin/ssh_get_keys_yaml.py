#!/usr/bin/python3
#
# Get specified user's keys and return in yaml format

import os
import pwd
import requests
import sys
import syslog
import yaml

def log_error(message):
    sys.stderr.write(f"{message}\n")

def get_ssh_keys(username):
    url = f"https://{config['host']}/v{API_VERSION}/ssh_keys/{username}"
    try:
        r = requests.get(url, auth=(config["username"], config["password"]))
        if r.status_code == 200:
            try:
                response = r.json()
                if response["status"] == "OK":
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

# Drop root privileges no longer required
pwentry = pwd.getpwnam(config["run_as"])
os.setgid(pwentry.pw_gid)
os.setgroups([])
os.setuid(pwentry.pw_uid)

keys = []
for key in get_ssh_keys(sys.argv[1]):
    keys.append(key)

print(yaml.dump(keys))
sys.stdout.flush()
