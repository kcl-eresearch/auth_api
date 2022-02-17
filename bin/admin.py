#!/usr/bin/python3

import argparse
import os
import pwd
import re
import requests
import sys
import yaml

def validate_user(user):
    if re.match(r"^[a-z0-9]+$", user):
        return user
    raise argparse.ArgumentTypeError("Invalid user")

def api_get(uri):
    url = f"https://{config['host']}/v{API_VERSION}/{uri}"
    try:
        r = requests.get(url, auth=(config["username"], config["password"]))
        if r.status_code == 200:
            response = r.json()
    except Exception as e:
        sys.stderr.write(f"Failed fetching {uri}: {e}\n")
        sys.exit(1)
    return response

API_VERSION = 1

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--user", type=validate_user)
parser.add_argument("-m", "--mfa", action="store_true")
args = parser.parse_args()

if args.user and args.mfa:
    sys.stderr.write("Cannot combine --user and --mfa options\n")
    sys.exit(1)

try:
    with open("/etc/auth_api.yaml") as fh:
        config = yaml.safe_load(fh)
except Exception as e:
    sys.stderr.write(f"Failed loading config: {e}\n")
    sys.exit(1)
