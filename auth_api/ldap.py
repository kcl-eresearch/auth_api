import ldap
import sys
import traceback
from flask import current_app
from ldap import filter

"""
Initialise LDAP connection
"""


def init_ldap():
    try:
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        ldap.set_option(
            ldap.OPT_X_TLS_CACERTFILE, current_app.config["ldap"]["ca_file"]
        )
        ldapc = ldap.initialize(f"ldaps://{current_app.config['ldap']['host']}:636")
        ldapc.set_option(ldap.OPT_REFERRALS, 0)
        ldapc.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldapc.simple_bind_s(
            current_app.config["ldap"]["bind_dn"], current_app.config["ldap"]["bind_pw"]
        )
    except Exception:
        sys.stderr.write("Failed connecting to LDAP:\n")
        sys.stderr.write(traceback.format_exc())
        return False

    return ldapc


"""
Get a user's details from LDAP
"""


def get_ldap_user(username):
    ldapc = init_ldap()
    filter = (
        "(&(objectClass=user)(sAMAccountName=%s)(!(memberOf:1.2.840.113556.1.4.1941:=%s)))"
        % (
            username,
            ldap.filter.escape_filter_chars(
                current_app.config["ldap"]["blocked_users_group"]
            ),
        )
    )
    result = ldapc.result(
        ldapc.search(
            current_app.config["ldap"]["base_dn"],
            ldap.SCOPE_SUBTREE,
            filter,
            ["mail", "givenName", "sn", "userAccountControl", "sAMAccountName"],
        )
    )
    ldapc.unbind_ext_s()

    if result[1] == [] or result[1][0][0] == None:
        return {}

    if "mail" not in result[1][0][1]:
        result[1][0][1]["mail"] = [f"{username}@kcl.ac.uk".encode()]

    return result[1][0][1]


"""
Retrieve sane display name from user LDAP entry
"""


def format_name(user_entry):
    if "givenName" in user_entry and "sn" in user_entry:
        return (user_entry["givenName"][0] + b" " + user_entry["sn"][0]).strip(b" -")
    elif "displayName" in user_entry:
        return user_entry["displayName"][0]
    return user_entry["sAMAccountName"][0]
