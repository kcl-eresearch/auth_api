import argparse
import mysql.connector
import os
import sys
import yaml

class mfa:
    cnx = None
    config = None

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--config_file", default="/etc/bastion_mfa.yaml")
        parser.add_argument("user")
        args = parser.parse_args()

        try:
            with open(args.config_file) as fh:
                self.config = yaml.safe_load(fh)
        except Exception as e:
            sys.stderr.write(f"Failed loading config from {args.config_file}: {e}\n")
            sys.exit(1)

        try:
            self.cnx = mysql.connector.connect(host=self.config["db"]["host"], user=self.config["db"]["user"], password=self.config["db"]["password"], database=self.config["db"]["database"])
        except Exception as e:
            sys.stderr.write(f"Failed connecting to database: {e}\n")
            sys.exit(1)
