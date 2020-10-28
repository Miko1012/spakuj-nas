import os
import requests
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = './static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    file = request.files['photo']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    url = 'https://infinite-hamlet-29399.herokuapp.com/sender/register'
    response = requests.post(url, data=request.form)
    print(request.form)
    print("status-code")
    print(response.status_code)
    if response.status_code != 200:
        return render_template('senderSignUp.html', message=response.text)
    return render_template('main.html')

    # url = 'aaa.com'
    # headers = {'Content-type': 'text/html; charset=UTF-8'}
    # response = requests.post(url, data=, headers=headers)
