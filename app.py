import json
import uuid

import requests
from bcrypt import checkpw, gensalt, hashpw
import datetime
from flask import Flask, render_template, request, make_response, session, flash, url_for, jsonify
from flask_cors import CORS, cross_origin
from dotenv import load_dotenv
from redis import StrictRedis
from os import getenv
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, get_raw_jwt, jwt_optional
)

load_dotenv()
REDIS_HOST = getenv("REDIS_HOST")
REDIS_PASS = getenv("REDIS_PASS")
db = StrictRedis(REDIS_HOST, db=7, password=REDIS_PASS)

SESSION_TYPE = "redis"
SESSION_REDIS = db
# SESSION_COOKIE_SECURE = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
app.secret_key = getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = 'alamakota'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_CSRF_CHECK_FORM'] = False
# app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
# app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
jwt = JWTManager(app)


STATUSES = {
    0: "nieprzypisana",
    1: "w drodze",
    2: "dostarczona",
    3: "odebrana"
}


def check_identity(identity):
    if identity is None:
        flash("Musisz się zalogować aby mieć dostęp do tej strony.", "error")
        return redirect(url_for('welcome'))
    return True


@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Create the new access token
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    # Set the JWT access cookie in the response
    resp = jsonify({'refresh': True})
    set_access_cookies(resp, access_token)
    return resp, 200


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


@app.route('/')
@jwt_optional
def welcome():
    return render_template('welcome.html', identity=get_jwt_identity())


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

        access_token = create_access_token(identity=login)
        refresh_token = create_refresh_token(identity=login)
        resp = jsonify({'login': login})
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        response = make_response(resp, 301)
        response.headers["Location"] = url_for('sender_dashboard')
        return response

    else:
        flash('Wystąpił błąd serwera - błędny typ żądania', 'error')
        return redirect(url_for(welcome))


@app.route('/sender/check-login-availability/<login>')
def is_user(login):
    return jsonify(available=(not db.hexists(f"user:{login}", "password")))


@app.route('/sender/logout')
@jwt_required
def sender_logout():
    identity = get_jwt_identity()
    check_identity(identity=identity)

    resp = jsonify({'logout': True})
    unset_jwt_cookies(resp)
    response = make_response(resp, 301)
    response.headers["Location"] = url_for('welcome')
    return response


@app.route('/sender/generate-label', methods=["GET", "POST"])
@jwt_required
def sender_generate_label():
    identity = get_jwt_identity()
    check_identity(identity)

    if request.method == 'GET':
        return render_template('senderGenerateLabel.html', identity=identity)

    elif request.method == 'POST':
        receiver = request.form.get("receiver")
        box = request.form.get("box")
        size = request.form.get("size")
        label_id = uuid.uuid4()

        if "" in [receiver, box, size]:
            flash("Wypełnij wszystkie pola formularza.", "error")
            return render_template('senderGenerateLabel.html', identity=identity)

        label = {
            "user": identity,
            "receiver": receiver,
            "box": box,
            "size": size,
            "label_id": str(label_id),
            "status": 0
        }
        db.hset(f"user:{identity}", f"label:{label_id}", json.dumps(label))
        flash("Dodano etykietę paczki!", "success")
        return redirect(url_for('sender_dashboard'))

    raise Exception('request method is neither post nor get')


@app.route('/sender/dashboard', methods=["GET", "POST"])
@jwt_required
def sender_dashboard():
    identity = get_jwt_identity()
    check_identity(identity)

    if request.method == 'GET':
        user = db.hgetall(f"user:{identity}")
        labels = []
        for obj in user:
            if obj.startswith(b'label'):
                label_data = db.hget(f"user:{identity}", obj)
                label_data = label_data.decode("UTF-8")
                label_data = json.loads(label_data)
                label_data["status"] = STATUSES[label_data["status"]]
                labels.append(label_data)
        return render_template('senderDashboard.html', labels=labels, identity=identity)


@app.route('/sender/delete-label/<label_uid>')
@jwt_required
def sender_delete_label(label_uid):
    identity = get_jwt_identity()
    check_identity(identity)

    user = db.hgetall(f"user:{identity}")
    label_to_delete = str.encode("label:" + label_uid)
    for obj in user:
        if obj == label_to_delete:
            db.hdel(f"user:{identity}", obj)
            flash('Etykieta została pomyślnie usunięta.', 'success')
            return redirect('/sender/dashboard')

    flash('Użytkownik nie posiada etykiety o podanym identyfikatorze.', "error")
    return redirect(url_for(sender_dashboard))


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
