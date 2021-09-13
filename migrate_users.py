#!/usr/bin/python

import mysql.connector
import sys
import yaml

try:
    with open("migrate_users.yaml") as fh:
        config = yaml.safe_load(fh)
except Exception as e:
    sys.stderr.write(f"Cannot load config: {e}\n")
    sys.exit(1)

try:
    cnx = mysql.connector.connect(host=config["db"]["host"], user=config["db"]["user"], password=config["db"]["password"])
except Exception as e:
    sys.stderr.write(f"Cannot connect DB: {e}\n")
    sys.exit(1)

users_migrated = []

try:
    cursor = cnx.cursor()
    cursor.execute("SELECT username FROM auth_api.users")
    for row in cursor:
        users_migrated.append(row[0])
except Exception as e:
    sys.stderr.write(f"Failed getting users from destination DB: {e}\n")
    sys.exit(1)

users_to_migrate = []

try:
    cursor = cnx.cursor()
    cursor.execute("SELECT username, display_name, email, deleted_at, created_at, updated_at FROM er_portal.users WHERE email LIKE '%@kcl.ac.uk'")
    for row in cursor:
        if row[0] not in users_migrated:
            users_to_migrate.append(row)

except Exception as e:
    sys.stderr.write(f"Failed getting users from source DB: {e}\n")
    sys.exit(1)

try:
    cursor = cnx.cursor()
    cursor.executemany("INSERT INTO auth_api.users(username, display_name, email, deleted_at, created_at, updated_at) VALUES(%s, %s, %s, %s, %s, %s)", users_to_migrate)
    cnx.commit()
except Exception as e:
    sys.stderr.write(f"Failed to migrate users: {e}\n")
    sys.exit(1)

user_ids = {}

try:
    cursor = cnx.cursor()
    cursor.execute("SELECT username, id FROM auth_api.users")
    for row in cursor:
        user_ids[row[0]] = row[1]
except Exception as e:
    sys.stderr.write(f"Failed getting usernames and ids from destination DB: {e}\n")
    sys.exit(1)

keys_migrated = {}

# Use just the actual key part, excluding names, due to duplicates
try:
    cursor = cnx.cursor(dictionary=True)
    cursor.execute("SELECT auth_api.users.username, auth_api.ssh_keys.type, auth_api.ssh_keys.name, auth_api.ssh_keys.pub_key FROM auth_api.ssh_keys INNER JOIN auth_api.users ON auth_api.ssh_keys.user_id = auth_api.users.id")
    for row in cursor:
        if row["username"] not in keys_migrated:
            keys_migrated[row["username"]] = []
        if row["pub_key"] not in keys_migrated[row["username"]]:
            keys_migrated[row["username"]].append(row["pub_key"])
except Exception as e:
    sys.stderr.write(f"Failed getting ssh keys from destination DB: {e}\n")
    sys.exit(1)

keys_to_import = []
user_key_names = {}
user_key_values = {}

try:
    cursor = cnx.cursor(dictionary=True)
    cursor.execute("SELECT `username`, `id`, `key`, `created_at` FROM er_portal.ssh_pubkeys")
    for row in cursor:
        # Key name must be unique per user
        if row["username"] not in user_key_names:
            user_key_names[row["username"]] = []

        # Key value must be unique per user
        if row["username"] not in user_key_values:
            user_key_values[row["username"]] = []

        key_parts = row["key"].split(" ", 2)

        if key_parts[1] in user_key_values[row["username"]] or row["username"] in keys_migrated and key_parts[1] in keys_migrated[row["username"]]:
            continue

        user_key_values[row["username"]].append(key_parts[1])

        if len(key_parts) == 2 or key_parts[2] in user_key_names[row["username"]]:
            if len(key_parts) == 2:
                key_name = "%s_%d" % (row["username"], row["id"])
            else:
                key_name = "%s_%d" % (key_parts[2], row["id"])
        else:
            key_name = key_parts[2]
        key_name = key_name[:255]
        user_key_names[row["username"]].append(key_name)

        keys_to_import.append([user_ids[row["username"]], key_parts[0], key_name, key_parts[1][:1024], row["created_at"]])
except Exception as e:
    sys.stderr.write(f"Failed getting ssh keys from source DB: {e}\n")
    raise(e)
    sys.exit(1)

try:
    cursor = cnx.cursor()
    cursor.executemany("INSERT INTO auth_api.ssh_keys(user_id, type, name, pub_key, created_at) VALUES(%s, %s, %s, %s, %s)", keys_to_import)
    cnx.commit()
except Exception as e:
    sys.stderr.write(f"Failed migrating SSH keys: {e}\n")
    sys.exit(1)
