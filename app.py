from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt,
)
from flask_smorest import Api, Blueprint, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from datetime import timedelta

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "mysecretkey"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["PROPAGATE_EXCEPTIONS"] = True
app.config["API_TITLE"] = "Item API"
app.config["API_VERSION"] = "v1"
app.config["OPENAPI_VERSION"] = "3.0.3"
app.config["OPENAPI_URL_PREFIX"] = "/"
app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"

db = SQLAlchemy(app)
api = Api(app)
jwt = JWTManager(app)

jwt_blocklist = set()


@jwt.token_in_blocklist_loader
def is_token_revoked(jwt_header, jwt_payload):
    return jwt_payload["jti"] in jwt_blocklist


@jwt.expired_token_loader
def handle_expired_token(jwt_header, jwt_payload):
    return jsonify({"message": "Token expired", "error": "token_expired"}), 401


@jwt.invalid_token_loader
def handle_invalid_token(error):
    return jsonify({"message": "Invalid token", "error": "invalid_token"}), 401


@jwt.unauthorized_loader
def handle_missing_token(error):
    return jsonify({"message": "Token required", "error": "authorization_required"}), 401


@jwt.revoked_token_loader
def handle_revoked_token(jwt_header, jwt_payload):
    return jsonify({"message": "Token revoked", "error": "token_revoked"}), 401


class ItemModel(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username == "user" and password == "password":
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    jwt_blocklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200


class ItemSchema:
    def dump(self, obj):
        return {"id": obj.id, "name": obj.name, "price": obj.price}


item_schema = ItemSchema()

blp = Blueprint("Items", "items", description="Operations on items")


@blp.route("/item/<int:item_id>")
class ItemResource:
    @jwt_required()
    def get(self, item_id):
        item = ItemModel.query.get_or_404(item_id)
        return item_schema.dump(item), 200

    @jwt_required()
    def delete(self, item_id):
        item = ItemModel.query.get_or_404(item_id)
        db.session.delete(item)
        db.session.commit()
        return {"message": "Item deleted"}, 200

    @jwt_required()
    def put(self, item_id):
        data = request.get_json()
        item = ItemModel.query.get(item_id)

        if item:
            item.name = data["name"]
            item.price = data["price"]
        else:
            item = ItemModel(id=item_id, **data)

        db.session.add(item)
        db.session.commit()
        return item_schema.dump(item), 200


@blp.route("/item")
class ItemListResource:
    @jwt_required()
    def get(self):
        items = ItemModel.query.all()
        return [item_schema.dump(item) for item in items], 200

    @jwt_required()
    def post(self):
        data = request.get_json()
        item = ItemModel(**data)

        try:
            db.session.add(item)
            db.session.commit()
        except SQLAlchemyError:
            abort(500, message="Error inserting item")

        return item_schema.dump(item), 201


api.register_blueprint(blp)


@app.before_first_request
def create_tables():
    db.create_all()


if __name__ == "__main__":
    app.run(port=5000, debug=True)
