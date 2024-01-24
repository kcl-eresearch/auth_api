
import argparse
import re
import requests
import sys
import yaml

API_VERSION = 1

def get_config():
    try:
        with open("/etc/auth_api.yaml") as fh:
            config = yaml.safe_load(fh)
    except Exception as e:
        sys.stderr.write(f"Failed loading config: {e}\n")
        sys.exit(1)
    return config

def validate_user(user):
    if re.match(r"^[a-z0-9]+$", user):
        return user
    raise argparse.ArgumentTypeError("Invalid user")

def api_get(uri):
    config = get_config()
    url = f"https://{config['host']}/v{API_VERSION}/{uri}"
    response = {}
    try:
        r = requests.get(url, auth=(config["username"], config["password"]))
        if r.status_code == 200:
            response = r.json()
        else:
            sys.stderr.write("Could not retrieve data from API\n")
            sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"Failed fetching {uri}: {e}\n")
        sys.exit(1)
    return response
