import json
import requests
from bcrypt import checkpw, gensalt, hashpw
from flask import Flask, render_template, request, make_response, session, flash, url_for
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


def is_user(login):
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


@app.route('/')
def hello_world():
    return render_template('main.html')


@app.route('/sender/sign-up')
def sender_sign_up():
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
    session["logged-at"] = "now"
    print("Login successful, established session:")
    print(session)
    return redirect(url_for('hello_world'))


@app.route('/sender/register', methods=["POST"])
def sender_register():
    firstname = request.form.get("firstname")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    password = request.form.get("password")
    passwordrepeated = request.form.get("psswordRepeated")
    login = request.form.get("login")
    address = request.form.get("address")
    # print("firstname: " + firstname + " lastname: " + lastname + " password: " + password)

    if not firstname:
        flash("No firstname provided")

    if not lastname:
        flash("No lastname provided")

    if not email:
        flash("No email provided")

    if not password:
        flash("No password provided")

    if password != passwordrepeated:
        flash("Passwords do not match")

    print(f"Registering {login}...")
    #TODO zobaczyć czy user istnieje w bazie danych

    save_user(firstname, lastname, email, password, login, address)

    response = make_response("", 301)
    response.headers["Location"] = "/sender/login"
    return response
    # return render_template('senderSignUp.html')


@app.route('/check/sender/check-login-availability/<username>')
def sender_check_login_availability(username):
    r = requests.get('https://infinite-hamlet-29399.herokuapp.com/check/' + username).content
    a = json.loads(r)
    return a
    # print(a)
    # if a[username] is "available":
    #     print("available")
    # else:
    #     print("taken")
    #
    # return "ok"


@app.route('/sender/logout')
def sender_logout():
    print("Logging out, clearing session:")
    print(session)
    session.clear()

    response = make_response("", 301)
    response.headers["Location"] = "/"
    return response
