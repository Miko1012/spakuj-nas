import json

import requests
from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def hello_world():
    return render_template('main.html')


@app.route('/sender/sign-up')
def sender_sign_up():
    return render_template('senderSignUp.html')


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
