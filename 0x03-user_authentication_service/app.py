#!/usr/bin/env python3
"""This module contains the app module"""
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth
from doctest import ELLIPSIS_MARKER


app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'], strict_slashes=False)
def message_welcome():
    """End-point to display a message"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_user():
    """Route to register a user """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": f"{email}", "message": "user created"}), 200
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login_sessions():
    """Login function to respond to the POST method"""
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email, password):
        sessionID = AUTH.create_session(email)
        res = jsonify({
            "email": email,
            "message": "logged in"})
        res.set_cookie('session_id', sessionID)
        return res
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout_sessions():
    """A logout function to respond to the DELETE method
    """
    session_id = request.cookies.get('session_id')
    user_session = AUTH.get_user_from_session_id(session_id)
    if user_session:
        AUTH.destroy_session(user_session.id)
        return redirect('/')
    else:
        abort(403)


@app.route('/profile', methods=['GET'], strict_slashes=False)
def get_user_profile():
    """A profile function to respond to the GET method"""
    session_id = request.cookies.get('session_id')
    user_session = AUTH.get_user_from_session_id(session_id)
    if user_session:
        return jsonify({"email": user_session.email}), 200
    else:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """A reset_password function to respond to the POST method
    """
    try:
        email = request.form.get('email')
        token_ = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token_}), 200
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """A function to respond to the PUT method
    to update the password
    """
    email = request.form.get('email')
    token_ = request.form.get('reset_token')
    password = request.form.get('new_password')
    try:
        AUTH.update_password(token_, password)
    except Exception:
        abort(403)
    return jsonify({"email": email, "message": "Password updated"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
