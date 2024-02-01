import os
import logging
import logging.handlers
import pymysql

logger = logging.getLogger("AuthAPI")
handler = logging.handlers.SysLogHandler(address="/dev/log")
logger.addHandler(handler)

from dotenv import load_dotenv
from flask import Flask, g
from flask_wtf.csrf import CSRFProtect
from flaskext.mysql import MySQL
from auth_api.common import get_config

csrf = CSRFProtect()

def create_app():
    load_dotenv()

    app = Flask(__name__)
    csrf.init_app(app)

    mysql = MySQL(app=None, prefix="mysql", cursorclass=pymysql.cursors.DictCursor)
    mysql.init_app(app)
    app.db = mysql

    app.config["migrations_path"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../db/migrations")
    )
    app.config["templates_path"] = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "templates")
    )
    app.config["authapi"] = get_config("/etc/auth_api/main.yaml")
    app.config["smtp"] = get_config("/etc/auth_api/smtp.yaml")
    app.config["ldap"] = get_config("/etc/auth_api/ldap.yaml")
    app.config["ca"] = get_config("/etc/auth_api/ca.yaml")
    app.config.update(get_config("/etc/auth_api/db.yaml"))

    migrate_database(mysql, app.config["migrations_path"])

    # Register the API.
    from auth_api.views.api import api_v1
    app.register_blueprint(api_v1)
    csrf.exempt(api_v1)

    # Register the dashboard.
    if app.config["authapi"]["dashboard"]["enabled"]:
        from auth_api.views.dashboard import dashboard
        app.register_blueprint(dashboard)

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
