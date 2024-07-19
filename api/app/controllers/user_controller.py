from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
from app.models.user_model import User
from app.utils.decorators import jwt_required_custom, roles_required
import json

user_bp = Blueprint("user", __name__)

@user_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", ["user"])
    if not username or not password:
        return jsonify({"error": "Se requieren nombre de usuario y contraseña"}), 400

    existing_user = User.find_by_username(username)
    if existing_user:
        return jsonify({"error": "El nombre de usuario ya está en uso"}), 400

    new_user = User(username=username, password=password, role=role)
    new_user.save()

    return jsonify({"message": "Usuario creado exitosamente"}), 201

@user_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = User.find_by_username(username)
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity={"username": username, "roles": user.role})
        refresh_token = create_refresh_token(identity={"username": username, "roles": user.role})
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    else:
        return jsonify({"error": "Credenciales inválidas"}), 401

@user_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token)

@user_bp.route("/profile", methods=["GET"])
@jwt_required_custom
def profile():
    current_user = get_jwt_identity()
    user = User.find_by_username(current_user['username'])
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    return jsonify({
        "username": user.username,
        "roles": json.loads(user.role)
    }), 200

@user_bp.route("/logout")
def logout():
    return jsonify({"message": "Logout endpoint"}), 200