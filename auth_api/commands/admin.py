#!/usr/bin/python3

import argparse
import datetime
import sys
import tabulate
import yaml

from auth_api.common import api_get, validate_user

def heading(string):
    print("%s\n%s" % (string, "=" * len(string)))

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--user", type=validate_user)
parser.add_argument("-m", "--mfa", action="store_true")
args = parser.parse_args()

if args.user and args.mfa:
    sys.stderr.write("Cannot combine --user and --mfa options\n")
    sys.exit(1)

if not (args.user or args.mfa):
    sys.stderr.write("Please specify either --mfa or --user USER\n")
    sys.exit(1)

if args.user:
    heading(f"SSH keys for {args.user}")
    ssh_keys = api_get(f"ssh_keys/{args.user}")
    for key in ssh_keys["keys"]:
        print()
        print(f"Name: {key['name']}")
        print(f"Created: {datetime.datetime.fromtimestamp(key['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Key: {key['type']} {key['pub_key']}")
    
    print()
    
    heading(f"VPN certificates for {args.user}")
    vpn_keys = api_get(f"vpn_keys/{args.user}")
    for key in vpn_keys["keys"]:
        print()
        print(f"Name: {key['name']}")
        print(f"UUID: {key['uuid']}")
        print(f"Status: {key['status']}")
        print(f"Created: {datetime.datetime.fromtimestamp(key['created_at']).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Expires: {datetime.datetime.fromtimestamp(key['expires_at']).strftime('%Y-%m-%d %H:%M:%S')}")
        print("Public certificate:")
        print(key["public_cert"])
    
    print()

    heading(f"MFA requests for {args.user}")    
    mfa_requests = api_get(f"mfa_requests/{args.user}")
    to_print = []
    for mfa in mfa_requests["mfa_requests"]:
        row = {}
        row["Created"] = datetime.datetime.fromtimestamp(mfa["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        row["Updated"] = datetime.datetime.fromtimestamp(mfa["updated_at"]).strftime("%Y-%m-%d %H:%M:%S")
        if mfa["expires_at"]:
            row["Expires"] = datetime.datetime.fromtimestamp(mfa["expires_at"]).strftime("%Y-%m-%d %H:%M:%S")
        else:
            row["Expires"] = "n/a"
        row["Service"] = mfa["service"]
        row["IP address"] = mfa["remote_ip"]
        row["Status"] = mfa["status"]
        to_print.append(row)
    
    print(tabulate.tabulate(to_print, headers="keys"))

if args.mfa:
    heading("MFA requests for all users")
    mfa_requests = api_get("mfa_requests")
    to_print = []
    for mfa in mfa_requests["mfa_requests"]:
        row = {}
        row["Username"] = mfa["username"]
        row["Created"] = datetime.datetime.fromtimestamp(mfa["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        row["Updated"] = datetime.datetime.fromtimestamp(mfa["updated_at"]).strftime("%Y-%m-%d %H:%M:%S")
        if mfa["expires_at"]:
            row["Expires"] = datetime.datetime.fromtimestamp(mfa["expires_at"]).strftime("%Y-%m-%d %H:%M:%S")
        else:
            row["Expires"] = "n/a"
        row["Service"] = mfa["service"]
        row["IP address"] = mfa["remote_ip"]
        row["Status"] = mfa["status"]
        to_print.append(row)
    
    print(tabulate.tabulate(to_print, headers="keys"))
