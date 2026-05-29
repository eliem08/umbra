from flask import Flask, Blueprint
# We can mock jwt_required or import it
def jwt_required():
    return lambda f: f

app = Flask(__name__)
bp = Blueprint("items", __name__)

# Documented & Authorized Blueprint Route
@bp.route("/api/v1/items", methods=["GET"])
@jwt_required()
def get_items():
    return {"items": []}

app.register_blueprint(bp)

# Non-Auth Public Route (Documented but no auth)
@app.route("/info", methods=["GET"])
def get_info():
    return {"version": "1.0.0"}

# Shadow API Route (Undocumented and no auth)
@app.route("/api/v1/internal-status")
def get_internal_status():
    return {"status": "debug"}
