from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
import requests



app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class SignupForm(FlaskForm):
    username = StringField('Username')
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Signup')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Successfully signed up! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/add_user/<username>/<email>', methods=['GET'])
def add_user(username, email):
    new_user = User(username=username, email=email)
    db.session.add(new_user)
    db.session.commit()
    return f'User {new_user.username} added.'

@app.route('/users', methods=['GET'])
def list_users():
    users = User.query.all()
    return '<br>'.join([f'User: {user.username}, Email: {user.email}' for user in users])

@app.route('/update', methods=['GET', 'POST'])
def update_user():
    if request.method == 'POST':
        username = request.form['username']
        new_email = request.form['new_email']
        user = User.query.filter_by(username=username).first()
        if user:
            user.email = new_email
            db.session.commit()
            return f'Email updated for user {username}.'
        else:
            return f'User {username} does not exist.'
    return render_template('update.html')

@app.route('/delete/<username>', methods=['GET'])
@login_required
def delete_user(username):
    if current_user.username == username:
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('delete.html', username=username)
    return redirect(url_for('home'))

@app.route('/confirm_delete/<username>', methods=['POST'])
@login_required
def confirm_delete(username):
    if current_user.username == username:
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            session.pop('user_id', None)
            logout_user()
            flash('Your account has been deleted.')
            return redirect(url_for('signup'))
    return redirect(url_for('home'))





@app.route('/random_dog', methods=['GET'])
def random_dog():
    response = requests.get('https://api.thedogapi.com/v1/images/search')
    if response.status_code == 200:
        data = response.json()
        return f"<img src='{data[0]['url']}'>"
        #return f"<img src='{data['message']}'>"
    else:
        # You can render a template with an error message instead of this.
        return "Failed to fetch random dog image!", 500


#https://api.thedogapi.com/v1/images/search #new api link???????????????????????????????????????????
#old api link: https://dog.ceo/api/breeds/image/random


""" swapping out TEST for random_dog#########################################ABOVE

@app.route('/random_dog', methods=['GET'])
def random_dog():
    response = requests.get('https://dog.ceo/api/breeds/image/random')
    data = response.json()
    return f"<img src='{data['message']}'>"

"""




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()































































"""   v.2 here below------DEPRECATED--------****************************************************************************************************


from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class SignupForm(FlaskForm):
    username = StringField('Username')
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Signup')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Successfully signed up! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/add_user/<username>/<email>', methods=['GET'])
def add_user(username, email):
    new_user = User(username=username, email=email)
    db.session.add(new_user)
    db.session.commit()
    return f'User {new_user.username} added.'

@app.route('/users', methods=['GET'])
def list_users():
    users = User.query.all()
    return '<br>'.join([f'User: {user.username}, Email: {user.email}' for user in users])

@app.route('/update', methods=['GET', 'POST'])
def update_user():
    if request.method == 'POST':
        username = request.form['username']
        new_email = request.form['new_email']
        user = User.query.filter_by(username=username).first()
        if user:
            user.email = new_email
            db.session.commit()
            return f'Email updated for user {username}.'
        else:
            return f'User {username} does not exist.'
    return render_template('update.html')

@app.route('/delete/<username>', methods=['GET'])
@login_required
def delete_user(username):
    if current_user.username == username:
        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('delete.html', username=username)
    return redirect(url_for('home'))




# ...reviwed per documentstion/delete acct-logout prob----------------

@app.route('/confirm_delete/<username>', methods=['POST'])
@login_required
def confirm_delete(username):
    if current_user.username == username:
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            logout_user()  # Log out the user
            return redirect(url_for('signup'))  # Redirect to signup page
    return redirect(url_for('home'))

# ...reviwed per documentstion/delete acct-logout prob----------------






@app.route('/random_dog', methods=['GET'])
def random_dog():
    response = requests.get('https://dog.ceo/api/breeds/image/random')
    data = response.json()
    return f"<img src='{data['message']}'>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()



v.2 here above------DEPRECATED--------****************************************************************************************************
"""














































#v.2 here below------DEPRECATED--------****************************************************************************************************
"""        

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from flask_login import current_user

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class SignupForm(FlaskForm):
    username = StringField('Username')
    email = StringField('Email')
    password = PasswordField('Password')
    submit = SubmitField('Signup')

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Successfully signed up! Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/add_user/<username>/<email>', methods=['GET'])
def add_user(username, email):
    new_user = User(username=username, email=email)
    db.session.add(new_user)
    db.session.commit()
    return f'User {new_user.username} added.'

@app.route('/users', methods=['GET'])
def list_users():
    users = User.query.all()
    return '<br>'.join([f'User: {user.username}, Email: {user.email}' for user in users])

@app.route('/update', methods=['GET', 'POST'])
def update_user():
    if request.method == 'POST':
        username = request.form['username']
        new_email = request.form['new_email']
        user = User.query.filter_by(username=username).first()
        if user:
            user.email = new_email
            db.session.commit()
            return f'Email updated for user {username}.'
        else:
            return f'User {username} does not exist.'
    return render_template('update.html')

@app.route('/delete/<username>', methods=['GET'])
def delete_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return f'User {username} deleted.'
    else:
        return f'User {username} does not exist.'

# Testing
@app.route('/random_dog', methods=['GET'])
def random_dog():
    response = requests.get('https://dog.ceo/api/breeds/image/random')
    data = response.json()
    return f"<img src='{data['message']}'>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run()





"""