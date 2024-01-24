import os
import logging
import logging.handlers

logger = logging.getLogger("AuthAPI")
handler = logging.handlers.SysLogHandler(address="/dev/log")
logger.addHandler(handler)

from dotenv import load_dotenv
from flask import Flask, g
from flaskext.mysql import MySQL
from auth_api.common import get_config


def create_app():
    load_dotenv()

    app = Flask(__name__)

    mysql = MySQL()
    mysql.init_app(app)

    app.config["migrations_path"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../db/migrations")
    )
    app.config["templates_path"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../templates")
    )
    app.config["authapi"] = get_config("/etc/auth_api/main.yaml")
    app.config["smtp"] = get_config("/etc/auth_api/smtp.yaml")
    app.config["ldap"] = get_config("/etc/auth_api/ldap.yaml")
    app.config["ca"] = get_config("/etc/auth_api/ca.yaml")

    app.config["MYSQL_DATABASE_HOST"] = os.getenv("MYSQL_DATABASE_HOST")
    app.config["MYSQL_DATABASE_USER"] = os.getenv("MYSQL_DATABASE_USER")
    app.config["MYSQL_DATABASE_PASSWORD"] = os.getenv("MYSQL_DATABASE_PASSWORD")
    app.config["MYSQL_DATABASE_DB"] = os.getenv("MYSQL_DATABASE_DB")

    migrate_database(mysql, app.config["migrations_path"])

    # Register the API.
    from auth_api.views.api import api_v1
    app.register_blueprint(api_v1)

    # Register the SSH CLI.
    from auth_api.commands.ssh import cli_ssh
    app.register_blueprint(cli_ssh)

    # Register the VPN CLI.
    from auth_api.commands.vpn import cli_vpn
    app.register_blueprint(cli_vpn)

    # Register the admin CLI.
    from auth_api.commands.admin import cli_admin
    app.register_blueprint(cli_admin)

    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, "_database", None)
        if db is not None:
            db.close()

    return app


def migrate_database(mysql, migrations_path):
    with mysql.connect() as db:
        if not db:
            raise Exception("Could not connect to database")

        with db.cursor() as cursor:
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS migrations(migration VARCHAR(255))"
            )

        with db.cursor() as cursor:
            cursor.execute("SELECT migration FROM migrations")
            migrations = cursor.fetchall()

        # Get a list of migration files.
        migration_files = os.listdir(migrations_path)
        migration_files = [f for f in migration_files if f.endswith(".sql")]
        migration_files.sort()

        # Run migrations that haven't been run yet
        for migration_file in migration_files:
            if migration_file not in migrations:
                with open(os.path.join(migrations_path, migration_file)) as fh:
                    sql = fh.read().strip()
                with db.cursor() as cursor:
                    cursor.execute(sql)
                with db.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO migrations(migration) VALUES(%s)", [migration_file]
                    )
                db.commit()
