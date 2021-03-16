import argparse
import ldap
import mysql.connector
import os
import re
import sys
import syslog
import yaml

class auth_api:
    cnx = None
    config = {}
    ldapc = None

    '''
    Constructor
    '''
    def __init__(self, config_dir="/etc/auth_api"):
        for file in ["main", "ca", "db", "ldap"]:
            config_file = f"{config_dir}/{file}.yaml"
            try:
                with open(config_file) as fh:
                    self.config["file`"] = yaml.safe_load(fh)
            except Exception as e:
                syslog.syslog(syslog.LOG_ERR, f"Failed loading {config_file}: {e}")
                return False

        try:
            self.cnx = mysql.connector.connect(host=self.config["db"]["host"], user=self.config["db"]["user"], password=self.config["db"]["password"], database=self.config["db"]["database"])
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Failed connecting to database: {e}")
            return False

        return True

    '''
    Initialise LDAP connection
    '''
    def init_ldap(self):
        try:
            ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self.config["ldap"]["ca_file"])
            self.ldapc =  ldap.initialize(f"ldaps://{self.config['ldap']['host']}:636")
            self.ldapc.set_option(ldap.OPT_REFERRALS, 0)
            self.ldapc.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            self.ldapc.simple_bind_s(self.config["ldap"]["username"], self.config["ldap"]["password"])
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Failed connecting to LDAP: {e}")
            return False

        return True

    '''
    Get a user's details from LDAP
    '''
    def get_ldap_user(self, username):
        result = self.ldapc.result(self.ldapc.search(self.config["base_dn"], ldap.SCOPE_SUBTREE, f"(&(objectClass=user)({self.config['ldap']['attr_username']}={username}))", [self.config["ldap"]["attr_email"], self.config["ldap"]["attr_display_name"]]))
        if len(result) != 2:
            return {}

        return result[1][0][1]

    '''
    Get ID from database of relevant user - creating new entry if required
    '''
    def get_user_id(self, username):
        try:
            cursor = self.cnx.cursor(dictionary=True)
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            result = cursor.fetchall()
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Querying database for user failed: {e}")
            return False

        if len(result) == 1:
            return result[0]["id"]

        try:
            if not self.init_ldap():
                return False

            ldap_user = self.get_ldap_user(username)
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Querying LDAP for user failed: {e}")
            return False

        if ldap_user == {}:
            return 0

        try:
            cursor = self.cnx.cursor(dictionary=True)
            cursor.execute("INSERT INTO users(username, display_name, email) VALUES(%s, %s, %s)", (username, TBC, TBC))
            cursor.commit()
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            result = cursor.fetchall()
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Adding new user to database failed: {e}")
            return False

        if len(result) == 1:
            return result[0]["id"]

        syslog.syslog(syslog.LOG_ERR, "Could not find new user in database")
        return False

    '''
    Get a user's SSH keys
    '''
    def get_user_ssh_keys(self, username):
        user_id = self.get_user_id(username)
        if not user_id:
            return False

        try:
            cursor = self.cnx.cursor(dictionary=True)
            cursor.execute("SELECT type, pub_key FROM ssh_keys WHERE user_id = %s", (user_id,))
            result = cursor.fetchall()
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"Error getting ssh keys for {username}: {e}")
            return False

        return result

    '''
    Set a user's SSH keys
    '''
    def set_user_ssh_keys(self, username, ssh_keys):
        existing = get_user_ssh_keys(username)
        if not existing:
            return False
        
