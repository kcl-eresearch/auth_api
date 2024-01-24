#!/usr/bin/python3

import argparse
import click
import datetime
import sys
import tabulate
import yaml
import requests
import socket

from auth_api.common import api_get, validate_user
from flask import Blueprint, current_app
from auth_api.common import log_error, log_info, get_ssh_keys, get_config

cli_admin = Blueprint('admin', __name__)

def heading(string):
    print("%s\n%s" % (string, "=" * len(string)))


@cli_admin.cli.command('admin')
@click.option('-u', '--user', type=validate_user)
@click.option("-m", "--mfa", action="store_true")
def admin(user, mfa):
    if user and mfa:
        sys.stderr.write("Cannot combine --user and --mfa options\n")
        sys.exit(1)

    if not (user or mfa):
        sys.stderr.write("Please specify either --mfa or --user USER\n")
        sys.exit(1)

    if user:
        heading(f"SSH keys for {user}")
        ssh_keys = api_get(f"ssh_keys/{user}")
        for key in ssh_keys["keys"]:
            print()
            print(f"Name: {key['name']}")
            print(
                f"Created: {datetime.datetime.fromtimestamp(key['created_at']).strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(f"Key: {key['type']} {key['pub_key']}")

        print()

        heading(f"VPN certificates for {user}")
        vpn_keys = api_get(f"vpn_keys/{user}")
        for key in vpn_keys["keys"]:
            print()
            print(f"Name: {key['name']}")
            print(f"UUID: {key['uuid']}")
            print(f"Status: {key['status']}")
            print(
                f"Created: {datetime.datetime.fromtimestamp(key['created_at']).strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print(
                f"Expires: {datetime.datetime.fromtimestamp(key['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}"
            )
            print("Public certificate:")
            print(key["public_cert"])

        print()

        heading(f"MFA requests for {user}")
        mfa_requests = api_get(f"mfa_requests/{user}")
        to_print = []
        for mfa_req in mfa_requests["mfa_requests"]:
            row = {}
            row["Created"] = datetime.datetime.fromtimestamp(mfa_req["created_at"]).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            row["Updated"] = datetime.datetime.fromtimestamp(mfa_req["updated_at"]).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if mfa_req["expires_at"]:
                row["Expires"] = datetime.datetime.fromtimestamp(
                    mfa_req["expires_at"]
                ).strftime("%Y-%m-%d %H:%M:%S")
            else:
                row["Expires"] = "n/a"
            row["Service"] = mfa_req["service"]
            row["IP address"] = mfa_req["remote_ip"]
            row["Status"] = mfa_req["status"]
            to_print.append(row)

        print(tabulate.tabulate(to_print, headers="keys"))

    if mfa:
        heading("MFA requests for all users")
        mfa_requests = api_get("mfa_requests")
        to_print = []
        for mfa_req in mfa_requests["mfa_requests"]:
            row = {}
            row["Username"] = mfa_req["username"]
            row["Created"] = datetime.datetime.fromtimestamp(mfa_req["created_at"]).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            row["Updated"] = datetime.datetime.fromtimestamp(mfa_req["updated_at"]).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if mfa_req["expires_at"]:
                row["Expires"] = datetime.datetime.fromtimestamp(
                    mfa_req["expires_at"]
                ).strftime("%Y-%m-%d %H:%M:%S")
            else:
                row["Expires"] = "n/a"
            row["Service"] = mfa_req["service"]
            row["IP address"] = mfa_req["remote_ip"]
            row["Status"] = mfa_req["status"]
            to_print.append(row)

        print(tabulate.tabulate(to_print, headers="keys"))

@cli_admin.cli.command('update_users')
def update_users():
    config = get_config("/etc/auth_api/maint_auth.yaml")

    fqdn = socket.getfqdn()
    url = f"https://{fqdn}/v1/maint/update_users"

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
