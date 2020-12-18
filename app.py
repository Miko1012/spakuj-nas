import json
import uuid

import requests
from bcrypt import checkpw, gensalt, hashpw
import datetime
from flask import Flask, render_template, request, make_response, session, flash, url_for, jsonify
from flask_cors import CORS, cross_origin
from flask_session import Session
from dotenv import load_dotenv
from redis import StrictRedis
from os import getenv
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)

load_dotenv()
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
db = StrictRedis(REDIS_HOST, db=7, password=REDIS_PASS)

SESSION_TYPE = "redis"
SESSION_REDIS = db
SESSION_COOKIE_SECURE = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
app.secret_key = getenv("SECRET_KEY")
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_SECRET_KEY'] = 'alamakota'
jwt = JWTManager(app)
# ses = Session(app)


STATUSES = {
    0: "nieprzypisana",
    1: "w drodze",
    2: "dostarczona",
    3: "odebrana"
}


def login_taken(login):
    return db.hexists(f"user:{login}", "password")


def save_user(firstname, lastname, email, password, login, address):
    salt = gensalt(5)
    password = password.encode()
    hashed = hashpw(password, salt)
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


@app.route('/sender/register', methods=["GET", "POST"])
def sender_register():
    if request.method == "GET":
        return render_template('senderRegister.html')

    elif request.method == "POST":
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        email = request.form.get("email")
        password = request.form.get("password")
        password_repeated = request.form.get("passwordRepeated")
        login = request.form.get("login")
        address = request.form.get("address")

        if not firstname:
            flash("No firstname provided", "error")
            return render_template('senderRegister.html')

        if not lastname:
            flash("No lastname provided", "error")
            return render_template('senderRegister.html')

        if not email:
            flash("No email provided", "error")
            return render_template('senderRegister.html')

        if not password:
            flash("No password provided", "error")
            return render_template('senderRegister.html')

        if password != password_repeated:
            flash("Passwords do not match", "error")
            return render_template('senderRegister.html')

        if login_taken(login):
            flash("Login already taken", "error")
            return render_template('senderRegister.html')

        save_user(firstname, lastname, email, password, login, address)
        flash("Pomyślnie zarejestrowano użytkownika.", "success")
        response = make_response("", 301)
        response.headers["Location"] = "/sender/login"
        return response

    else:
        flash('Wystąpił błąd serwera - błędny typ żądania', 'error')
        return render_template("welcome.html")


@app.route('/sender/login', methods=["GET", "POST"])
def sender_login():
    if request.method == "GET":
        return render_template('senderLogin.html')

    elif request.method == "POST":
        login = request.form.get("login")
        password = request.form.get("password")

        if not login or not password:
            flash("Niepoprawne dane logowania!", "error")
            return redirect(url_for('sender_login'))

        if not verify_user(login, password):
            flash("Niepoprawne dane logowania!", "error")
            return redirect(url_for('sender_login'))

        session["login"] = login
        session["logged-at"] = datetime.now()
        return redirect(url_for('sender_dashboard'))

    else:
        flash('Wystąpił błąd serwera - błędny typ żądania', 'error')
        return render_template("welcome.html")


@app.route('/sender/check-login-availability/<login>')
def is_user(login):
    return jsonify(available=(not db.hexists(f"user:{login}", "password")))


@app.route('/sender/logout')
def sender_logout():
    if 'login' not in session:
        flash("Musisz się zalogować aby się wylogować :)", "error")
        return redirect(url_for('welcome'))

    session.clear()

    response = make_response("", 301)
    response.headers["Location"] = "/"
    return response


@app.route('/sender/generate-label', methods=["GET", "POST"])
def sender_generate_label():
    if 'login' not in session:
        flash("Musisz się zalogować aby mieć dostęp do tej strony.", "error")
        return redirect(url_for('welcome'))

    if request.method == 'GET':
        return render_template('senderGenerateLabel.html')

    elif request.method == 'POST':
        user = session["login"]
        receiver = request.form.get("receiver")
        box = request.form.get("box")
        size = request.form.get("size")
        label_id = uuid.uuid4()

        if "" in [receiver, box, size]:
            flash("Wypełnij wszystkie pola formularza.", "error")
            return render_template('senderGenerateLabel.html')

        label = {
            "user": user,
            "receiver": receiver,
            "box": box,
            "size": size,
            "label_id": str(label_id),
            "status": 0
        }
        db.hset(f"user:{session['login']}", f"label:{label_id}", json.dumps(label))
        flash("Dodano etykietę paczki!", "success")
        return redirect(url_for('sender_dashboard'))

    raise Exception('request method is neither post nor get')


@app.route('/sender/dashboard', methods=["GET", "POST"])
def sender_dashboard():
    if 'login' not in session:
        flash("Musisz się zalogować aby mieć dostęp do tej strony.", "error")
        return redirect(url_for('welcome'))

    if request.method == 'GET':
        user = db.hgetall(f"user:{session['login']}")
        labels = []
        for obj in user:
            if obj.startswith(b'label'):
                label_data = db.hget(f"user:{session['login']}", obj)
                label_data = label_data.decode("UTF-8")
                label_data = json.loads(label_data)
                label_data["status"] = STATUSES[label_data["status"]]
                labels.append(label_data)
        return render_template('senderDashboard.html', labels=labels)


@app.route('/sender/delete-label/<label_uid>')
def sender_delete_label(label_uid):
    if 'login' not in session:
        flash("Musisz się zalogować aby mieć dostęp do tej strony.", "error")
        return redirect(url_for('welcome'))

    user = db.hgetall(f"user:{session['login']}")
    label_to_delete = str.encode("label:" + label_uid)
    for obj in user:
        if obj == label_to_delete:
            db.hdel(f"user:{session['login']}", obj)
            flash('Etykieta została pomyślnie usunięta.', 'success')
            return redirect('/sender/dashboard')

    flash('Użytkownik nie posiada etykiety o podanym identyfikatorze.', "error")
    return redirect('/sender/dashboard')


@app.route('/courier/dashboard', methods=["GET"])
@cross_origin()
def courier_dashboard():
    users = db.keys("user:*")
    labels = []
    for user in users:
        user = user.decode()
        user_data = db.hgetall(f"{user}")
        for obj in user_data:
            if obj.startswith(b'label'):
                label_data = db.hget(f"{user}", obj)
                label_data = label_data.decode("UTF-8")
                label_data = json.loads(label_data)
                label_data["status"] = STATUSES[label_data["status"]]
                # if label_data < (len(STATUSES) - 1):
                #
                # labels.append(label_data)
    response = make_response(json.dumps(labels), 200)
    return response


if __name__ == "__main__":
    app.run(ssl_context='adhoc', host="127.0.0.1", port=5000, debug=True)
