validateForm = () => {

}

isValid = (field, value) => {
    let LETTERS = 'AĄBCĆDEĘFGHIJKLŁMNŃOÓPQRSŚTUVWXYZŹŻ';
    let letters = 'aąbcćdeęfghijklłmnńoópqrsśtuvwxyzźż';

    switch (field) {
        case 'firstname':
        case 'lastname':
            const nameRegexp = new RegExp('^[' + LETTERS + '][' + letters + ']+');
            return nameRegexp.exec(value) !== null;
        case 'sex':
            console.log(value === 'M' || value === 'F');
            return value === 'M' || value === 'F';
        case 'login':
        case 'password':
            const passwordRegexp = new RegExp('.{8,}');
            console.log(passwordRegexp.exec(value) !== null);
            return passwordRegexp.exec(value) !== null;
        case 'passwordRepeated':

        case 'photo':

    }
}

window.onload = () => {

    let firstname = document.getElementById('firstname');
    let lastname = document.getElementById('lastname');
    let sex = document.getElementById('sex')
    let login = document.getElementById('login');
    let password = document.getElementById('password');
    let passwordRepeated = document.getElementById('passwordRepeated');
    let photo = document.getElementById('photo');


    firstname.addEventListener('input', (e) => {
        if(isValid('firstname', e.target.value)) {
            firstname.classList.remove("invalid-field");
            firstname.classList.add("valid-field");
        } else {
            firstname.classList.remove("valid-field");
            firstname.classList.add("invalid-field");
        }
    });

    lastname.addEventListener('input', (e) => {
        if(isValid('lastname', e.target.value)) {
            lastname.classList.remove("invalid-field");
            lastname.classList.add("valid-field");
        } else {
            lastname.classList.remove("valid-field");
            lastname.classList.add("invalid-field");
        }
    });

    sex.addEventListener('input', (e) => {
        if(isValid('sex', e.target.value)) {
            sex.classList.remove("invalid-field");
            sex.classList.add("valid-field");
        } else {
            sex.classList.remove("valid-field");
            sex.classList.add("invalid-field");
        }
    });

    login.addEventListener('input', (e) => {
        if(isValid('login', e.target.value)) {
            login.classList.remove("invalid-field");
            login.classList.add("valid-field");
        } else {
            login.classList.remove("valid-field");
            login.classList.add("invalid-field");
        }
    });

    password.addEventListener('input', (e) => {
        if(isValid('password', e.target.value)) {
            password.classList.remove("invalid-field");
            password.classList.add("valid-field");
        } else {
            password.classList.remove("valid-field");
            password.classList.add("invalid-field");
        }
    });

    passwordRepeated.addEventListener('input', (e) => {
        isValid('passwordRepeated', e.target.value);
    });

    photo.addEventListener('change', (e) => {
        isValid('firstname', e.target.value);
    });

}
