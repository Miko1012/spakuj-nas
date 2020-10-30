let availableLogin = false;

validateForm = (firstname, lastname, sex, login, password, passwordRepeated, photo) => {
    if(!isValid('firstname', firstname)) {
        alert("Niepoprawne imię!");
        return false;
    }
    if(!isValid('lastname', lastname)) {
        alert("Niepoprawne nazwisko!");
        return false;
    }
    if(!isValid('sex', sex)) {
        alert("Niepoprawna płeć!");
        return false;
    }
    if(!isValid('login', login)) {
        alert("nieprawidłowy login!");
        return false;
    }
    if(!isValid('password', password)) {
        alert("Niepoprawne hasło!");
        return false;
    }
    if(password !== passwordRepeated) {
        alert("Podane hasła nie są zgodne!");
        return false;
    }
    if(photo === '') {
        alert("Niepoprawne lub niezałączone zdjęcie!");
        return false;
    }
    if(!availableLogin) {
        alert("Ten login jest już zajęty!");
        return false;
    }
    return true;
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
            return value === 'M' || value === 'F';
        case 'login':
        case 'password':
            const passwordRegexp = new RegExp('.{8,}');
            return passwordRegexp.exec(value) !== null;
        case 'photo':
            return value !== '';
    }
}

registerSender = (e) => {

    if(!validateForm(
        e.target["firstname"].value,
        e.target["lastname"].value,
        e.target["sex"].value,
        e.target["login"].value,
        e.target["password"].value,
        e.target["passwordRepeated"].value,
        e.target["photo"].value,
        ) || !availableLogin) {
        e.preventDefault();
    }
}

isLoginAvailable = async (login) => {
    const response = await fetch('/check/sender/check-login-availability/' + login).then((r) => r.json());
    availableLogin = response[login] === "available";
    return response[login] === "available";
}

window.onload = () => {

    let firstname = document.getElementById('firstname');
    let lastname = document.getElementById('lastname');
    let sex = document.getElementById('sex')
    let login = document.getElementById('login');
    let password = document.getElementById('password');
    let passwordRepeated = document.getElementById('passwordRepeated');
    let photo = document.getElementById('photo');
    let form = document.getElementById('form');
    let loginAvailability = document.getElementById('login-availability');

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
            isLoginAvailable(e.target.value).then((available) => {
                if(available === true) {
                    loginAvailability.classList.add("hidden");
                    login.classList.remove("invalid-field");
                    login.classList.add("valid-field");
                } else {
                    loginAvailability.classList.remove("hidden");
                    login.classList.remove("valid-field");
                    login.classList.add("invalid-field");
                }

            });
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
        if(isValid('password', password.value) && passwordRepeated.value === password.value) {
            passwordRepeated.classList.remove("invalid-field");
            passwordRepeated.classList.add("valid-field");
        } else {
            passwordRepeated.classList.remove("valid-field");
            passwordRepeated.classList.add("invalid-field");
        }
    });

    form.addEventListener('submit', (e) => {
        registerSender(e);
    });

}
