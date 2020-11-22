import json
import uuid

import requests
from bcrypt import checkpw, gensalt, hashpw
from datetime import datetime
from flask import Flask, render_template, request, make_response, session, flash, url_for, jsonify
from flask_session import Session
from dotenv import load_dotenv
from redis import StrictRedis
from jwt import encode, decode
from os import getenv

load_dotenv()
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
db = StrictRedis(REDIS_HOST, db=7, password=REDIS_PASS)

SESSION_TYPE = "redis"
SESSION_REDIS = db
app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = getenv("SECRET_KEY")
ses = Session(app)


def login_taken(login):
    return db.hexists(f"user:{login}", "password")


def save_user(firstname, lastname, email, password, login, address):
    salt = gensalt(5)
    password = password.encode()
    hashed = hashpw(password, salt)
    print(f"saving user with login:{login}, password: {password}, email: {email}")
    db.hset(f"user:{login}", "firstname", firstname)
    db.hset(f"user:{login}", "lastname", lastname)
    db.hset(f"user:{login}", "email", email)
    db.hset(f"user:{login}", "password", hashed)
    db.hset(f"user:{login}", "address", address)
    return True


def verify_user(login, password):
    password = password.encode()
    hashed = db.hget(f"user:{login}", "password")
    if not hashed:
        print(f"ERROR: No password for {login}")
        return False
    return checkpw(password, hashed)


def redirect(url, status=301):
    response = make_response('', status)
    response.headers['Location'] = url
    return response


def save_label(label):
    db.hset(f"user:{session['login']}", "label", label)
    return True


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/sender/sign-up')
def sender_sign_up_get():
    return render_template('senderSignUp.html')


@app.route('/sender/login', methods=["GET"])
def sender_login_get():
    return render_template('senderLogin.html')


@app.route('/sender/login', methods=["POST"])
def sender_login_post():
    login = request.form.get("login")
    password = request.form.get("password")

    if not login or not password:
        flash("Missing login and/or password")
        return redirect(url_for('sender_login_get'))

    if not verify_user(login, password):
        flash("Invalid login and/or password")
        return redirect(url_for('sender_login_get'))

    print(f"{login} verification result: {verify_user(login, password)}")

    flash(f"Witaj {login}!")
    session["login"] = login
    session["logged-at"] = datetime.now()
    print("Login successful, established session:")
    print(session)
    flash("ssij mi fiuta!")
    return redirect(url_for('welcome'))


@app.route('/sender/register', methods=["POST"])
def sender_register():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    password = request.form.get("password")
    password_repeated = request.form.get("passwordRepeated")
    login = request.form.get("login")
    address = request.form.get("address")

    if not firstname:
        flash("No firstname provided")
        return render_template('senderSignUp.html')

    if not lastname:
        flash("No lastname provided")
        return render_template('senderSignUp.html')

    if not email:
        flash("No email provided")
        return render_template('senderSignUp.html')

    if not password:
        flash("No password provided")
        return render_template('senderSignUp.html')

    if password != password_repeated:
        flash("Passwords do not match")
        return render_template('senderSignUp.html')

    if login_taken(login):
        flash("Login already taken")
        return render_template('senderSignUp.html')

    print(f"Registering {login}...")
    save_user(firstname, lastname, email, password, login, address)

    response = make_response("", 301)
    response.headers["Location"] = "/sender/login"
    return response


@app.route('/sender/check-login-availability/<login>')
def is_user(login):
    return jsonify(available=(not db.hexists(f"user:{login}", "password")))


@app.route('/sender/logout')
def sender_logout():
    print("Logging out, clearing session:")
    print(session)
    session.clear()

    response = make_response("", 301)
    response.headers["Location"] = "/"
    return response


@app.route('/sender/generate-label', methods=["GET", "POST"])
def sender_generate_label():
    print('dupa')
    print(request)
    if request.method == 'GET':
        return render_template('senderGenerateLabel.html')

    elif request.method == 'POST':
        user = session["login"]
        receiver = request.form.get("receiver")
        box = request.form.get("box")
        size = request.form.get("size")
        label_id = uuid.uuid4()

        # TODO spojrzeć czy powyższe nie są nullami

        label = {
            "user": user,
            "receiver": receiver,
            "box": box,
            "size": size,
            "label_id": str(label_id)
        }
        print(f"generating label:{label_id}")
        print(label)
        db.hset(f"user:{session['login']}", f"label:{label_id}", json.dumps(label))
        return redirect(url_for('welcome'))

    raise Exception('request method is neither post nor get')


@app.route('/sender/dashboard', methods=["GET", "POST"])
def sender_dashboard():
    if request.method == 'GET':
        user = db.hgetall(f"user:{session['login']}")
        labels = []
        for obj in user:
            if obj.startswith(b'label'):
                label_data = db.hget(f"user:{session['login']}", obj)
                label_data = label_data.decode("UTF-8")
                labels.append(label_data)
        return render_template('senderDashboard.html', labels=labels)
