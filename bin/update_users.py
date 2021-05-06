#!/usr/bin/python3

import requests
import socket
import sys
import syslog
import yaml

def log_error(message):
    syslog.syslog(syslog.LOG_ERR, message)
    sys.stderr.write(f"{message}\n")

def log_info(message):
    syslog.syslog(syslog.LOG_INFO, message)
    print(message)

# Must be integer
API_VERSION = 1

try:
    with open("/etc/auth_api/maint_auth.yaml") as fh:
        config = yaml.safe_load(fh)
except Exception as e:
    log_error(f"Failed loading config: {e}")
    sys.exit(1)

fqdn = socket.getfqdn()
url = f"https://{fqdn}/v{API_VERSION}/maint/update_users"

try:
    r = requests.post(url, auth=(config["username"], config["password"]))
except Exception as e:
    log_error(f"Failed during POST request: {e}")
    sys.exit(1)

if r.status_code != 200:
    log_error(f"Unexpected status code from POST: {r.status_code}")
    log_error("Response was:")
    log_error(r.text)
    sys.exit(1)

try:
    response = r.json()
except Exception as e:
    log_error(f"Failed decoding response: {e}")
    log_error("Response was:")
    log_error(r.text)
    sys.exit(1)

if response["status"] == "ERROR":
    log_error(f"Error status from API, detail: {response['detail']}")
    sys.exit(1)

log_info(f"OK, {response['changes']} changes")
