
from flask import Blueprint

api_v1 = Blueprint("apiv1", __name__, url_prefix="/api/v1")

@api_v1.route("/", methods=["GET"])
def api_index():
    return "Auth API Version 1"
