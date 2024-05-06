from flask import Flask, render_template, request, redirect, url_for, session, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '116'  # Replace with a strong secret key

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://john_doe:123412@localhost/databasename'
db = SQLAlchemy(app)

# User model definition
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(80))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(15))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Function to check if the user is logged in
def is_logged_in():
    return 'username' in session

# Home route for login/signup
@app.route('/', methods=['GET', 'POST'])
def home():
    if is_logged_in():
        return redirect(url_for('intrusion_detection'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'login':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                session['username'] = username
                return redirect(url_for('intrusion_detection'))
            else:
                return "Invalid username or password."

        elif action == 'signup':
            username = request.form.get('username')
            password = request.form.get('password')
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')

            user = User.query.filter_by(username=username).first()
            if user:
                return "Username already exists. Please choose a different username."

            new_user = User(username=username, name=name, email=email, phone=phone)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            session['username'] = username
            return redirect(url_for('intrusion_detection'))

    return render_template('index.html', logged_in=is_logged_in())

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Intrusion Detection route and function
@app.route('/intrusion_detection', methods=['GET', 'POST'])
def intrusion_detection():
    if not is_logged_in():
        return redirect(url_for('home'))

    if request.method == 'POST':
        result = "Attack Detected"
        return render_template('intrusion_detection.html', result=result)

    return render_template('intrusion_detection.html')

# New routes
@app.route('/login', methods=['POST'])
def login():
    return redirect(url_for('home'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    result = "Attack Detected"
    return render_template('intrusion_detection.html', result=result)

def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)


