from flask import Flask, render_template, request
import random,string,re,socket
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

@app.route('/')
def buttons():
    return render_template('main.html')

def is_strong_password(password):
    # Password strength checking logic
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*()-_=+|;:",<.>/?]', password):
        return False
    return True

@app.route('/password_checker', methods=['GET', 'POST'])
def password_checker():
    result = ""
    if request.method == 'POST':
        password = request.form['password']
        if is_strong_password(password):
            result = "Your password is strong!"
        else:
            result = "Your password is weak. Please choose a stronger password."
    return render_template('password_checker.html', result=result)

# ... (your existing email validation and index route)
def is_valid_email(email):
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

@app.route('/index', methods=['GET', 'POST'])
def index():
    message = ""
    if request.method == 'POST':
        email_address = request.form['email']
        if is_valid_email(email_address):
            message = "The email address is valid."
        else:
            message = "Invalid email address. Please enter a valid email."
    return render_template('index.html', message=message)

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

@app.route('/index_password', methods=['GET', 'POST'])
def index_password():
    generated_password = ""
    if request.method == 'POST':
        password_length = int(request.form['password_length'])
        if password_length < 1:
            generated_password = "Password length should be a positive integer."
        else:
            generated_password = generate_random_password(password_length)
    return render_template('index_password.html', generated_password=generated_password)

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                return f"Port {port} is open."
            else:
                return f"Port {port} is closed."
    except Exception as e:
        return f"An error occurred while scanning port {port}: {e}"

@app.route('/scanner_port', methods=['GET', 'POST'])
def scanner_port():
    result = ""
    if request.method == 'POST':
        target_ip = request.form['target_ip']
        start_port = int(request.form['start_port'])
        end_port = int(request.form['end_port'])

        with ThreadPoolExecutor() as executor:
            scan_results = list(executor.map(scan_port, [target_ip] * (end_port - start_port + 1), range(start_port, end_port + 1)))

        result = "\n".join(scan_results)

    return render_template('scanner_port.html', result=result)

if __name__ == "__main__":
    app.run(debug=True)
