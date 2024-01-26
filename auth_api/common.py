import argparse
import datetime
import jinja2
import os
import re
import requests
import smtplib
import sshpubkeys
import ssl
import sys
import syslog
import traceback
import yaml

from flask import current_app
from flaskext.mysql import MySQL

API_VERSION = 1

def log_error(message):
    syslog.syslog(syslog.LOG_ERR | syslog.LOG_AUTHPRIV, message)
    sys.stderr.write(f"{message}\n")


def log_info(message):
    syslog.syslog(syslog.LOG_INFO | syslog.LOG_AUTHPRIV, message)

def get_db():
    db = current_app.db.get_db()
    if not db:
        db = current_app.db.connect()
    if not db:
        raise Exception("Could not connect to database")
    return db


def get_config(filepath="/etc/auth_api.yaml"):
    try:
        with open(filepath) as fh:
            config = yaml.safe_load(fh)
    except Exception as e:
        sys.stderr.write(f"Failed loading config: {e}\n")
        sys.exit(1)
    return config


def validate_user(user):
    if re.match(r"^[a-z0-9]+$", user):
        return user
    raise argparse.ArgumentTypeError("Invalid user")


"""
Validate SSH public key
"""


def validate_ssh_key(type, pub_key, name):
    ssh_key = sshpubkeys.SSHKey(f"{type} {pub_key} {name}")
    try:
        ssh_key.parse()
    except Exception:
        return False
    return True


def api_get(uri):
    config = current_app.config["authapi"]

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


"""
Make list of dicts serializable - convert datetimes to unix timestamps
"""


def make_serializable(data):
    output = []
    for datum in data:
        my_output = {}
        for k, v in datum.items():
            if isinstance(v, datetime.datetime):
                my_output[k] = int(v.timestamp())
            else:
                my_output[k] = v
        output.append(my_output)
    return output


"""
Send email notification to user notifying of key changes
"""


def send_email(username, service):
    db = get_db()
    smtp_config = current_app.config["smtp"]

    try:
        with open(
            os.path.join(current_app.config["templates_path"], "mail_template.j2")
        ) as fh:
            mail_template = jinja2.Template(fh.read())
    except Exception:
        sys.stderr.write("Failed loading mail template:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    try:
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT display_name, email FROM users WHERE username = %s", (username,)
            )
            result = cursor.fetchall()
    except Exception:
        sys.stderr.write("Failed retrieving user details from database:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    if len(result) < 1:
        sys.stderr.write(f"Did not find user {username} in database\n")
        return False

    if result[0]["display_name"] == "":
        result[0]["display_name"] = username

    if result[0]["email"] == "":
        sys.stderr.write(f"Did not find email address for {username} in database\n")
        return False

    try:
        mail_message = mail_template.render(
            from_name=smtp_config["from_name"],
            from_addr=smtp_config["from_addr"],
            display_name=result[0]["display_name"],
            user_email=result[0]["email"],
            service_name=service.upper(),
            username=username,
        )
    except Exception:
        sys.stderr.write("Failed rendering mail message:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    try:
        smtp = smtplib.SMTP(smtp_config["server"], smtp_config["port"])
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(smtp_config["username"], smtp_config["password"])
        smtp.sendmail(smtp_config["from_addr"], result[0]["email"], mail_message)
        smtp.quit()
    except Exception:
        sys.stderr.write("Failed sending mail message:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return True
