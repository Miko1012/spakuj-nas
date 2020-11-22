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
        case 'login':
        case 'password':
            const passwordRegexp = new RegExp('.{8,}');
            return passwordRegexp.exec(value) !== null;
        case 'passwordRepeated':
            return value === password.value;
        case 'address':
            return value !== null
        case 'email':
            const emailRegexp = new RegExp('^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$');
            return emailRegexp.exec(value) !== null;
    }
}

handleInput = (field, value, element) => {
    if(isValid(field, value)) {
            element.classList.remove("invalid-field");
            element.classList.add("valid-field");
        } else {
            element.classList.remove("valid-field");
            element.classList.add("invalid-field");
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

handleLoginAvailability = async (login, loginAvailability) => {
    if(isValid('login', login)) {
        const response = await fetch('/sender/check-login-availability/' + login).then((r) => r.json());
        if(response.available) {
            loginAvailability.classList.add("hidden")
        } else {
            loginAvailability.classList.remove("hidden")
        }
    }
}

window.onload = () => {

    let firstname = document.getElementById('firstname');
    let lastname = document.getElementById('lastname');
    let login = document.getElementById('login');
    let password = document.getElementById('password');
    let passwordRepeated = document.getElementById('passwordRepeated');
    let form = document.getElementById('form');
    let loginAvailability = document.getElementById('login-availability');
    let address = document.getElementById('address');
    let email = document.getElementById('email');

    firstname.addEventListener('input', (e) => {
        handleInput('firstname', e.target.value, firstname);
    });

    lastname.addEventListener('input', (e) => {
        handleInput('lastname', e.target.value, lastname);
    });

    login.addEventListener('input', (e) => {
        handleInput('login', e.target.value, login);
    });

    login.addEventListener('input', (e) => {
        handleLoginAvailability(e.target.value, loginAvailability);
    });

    password.addEventListener('input', (e) => {
        handleInput('password', e.target.value, password);
    });

    passwordRepeated.addEventListener('input', (e) => {
        handleInput('passwordRepeated', e.target.value, passwordRepeated);
    });

    address.addEventListener('input', (e) => {
        handleInput('address', e.target.value, address);
    });

    email.addEventListener('input', (e) => {
        handleInput('email', e.target.value, email);
    });

    form.addEventListener('submit', (e) => {
        registerSender(e);
    });

}
