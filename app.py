import re
import requests
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route('/')
def hello_world():
    return render_template('main.html')


@app.route('/sender/sign-up')
def sender_sign_up():
    return render_template('senderSignUp.html')


@app.route('/sender_register', methods=['POST'])
def sender_register():
    print(request.values)
    print('~~~~')
    print(request.form)
    url = 'https://infinite-hamlet-29399.herokuapp.com/sender/register'
    headers = {'Content-type': 'multipart/form-data; charset=UTF-8'}
    response = requests.post(url, data=request.form, headers=headers)
    if response.status_code != 200:
        return render_template('senderSignUp.html', message=response.text)
    return render_template('main.html')

    # url = 'aaa.com'
    # headers = {'Content-type': 'text/html; charset=UTF-8'}
    # response = requests.post(url, data=, headers=headers)
