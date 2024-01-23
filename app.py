from flask import Flask, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import secrets
from flask.cli import FlaskGroup
from bcrypt import hashpw, gensalt,checkpw
#from sqlalchemy import create_engine




app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'buda'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'victorfx7752@gmail.com'
app.config['MAIL_PASSWORD'] = 'fvwx hhai lsxs xpzu'



db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)



login_manager = LoginManager(app)
login_manager.login_view = 'login'



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(100))
    balance = db.Column(db.Float, default=10.0)

    def set_password(self, password):
        hashed_password = hashpw(password.encode('utf-8'), gensalt())
        self.password = hashed_password.decode('utf-8')

    def check_password(self, password):
        return checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, email={self.email}, balance={self.balance})"

# with app.app_context():
#         db.create_all()

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=20)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email is already taken.')

    def validate_password(self, field):
        password = field.data
        if len(password) < 6:
            raise ValidationError('Password must be at least 6 characters long.')

        if not any(char.isdigit() for char in password):
            raise ValidationError('Password must contain at least one number.')

        if not any(char.isalpha() for char in password):
            raise ValidationError('Password must contain at least one character.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters long.'),
        EqualTo('confirm_password', message='Passwords must match'),
        Regexp('^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!$%@#£€*?&]+$',
               message='Password must contain at least one letter and one number.')])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class ProfileUpdateForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    submit = SubmitField('Update Profile')


@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email is already taken.', 'danger')
            return redirect(url_for('register'))
        hashed_password = hashpw(form.password.data.encode('utf-8'), gensalt())
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_password.decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = secrets.token_urlsafe(20)
            user.reset_token = token
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Send reset link via email
            msg = Message('Password Reset Request', sender='victorfx7752@gmail.com', recipients=[user.email])
            msg.body = f'To reset your password, click the following link: {reset_link}'
            mail.send(msg)

            flash('An email with instructions to reset your password has been sent.', 'info')
        else:
            flash('No user found with that email address.', 'danger')

    return render_template('forgot_password.html', title='Forgot Password', form=form)



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if user:
        form = ResetPasswordForm()
        if form.validate_on_submit():
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match. Please try again.', 'danger')
                return render_template('reset_password.html', title='Reset Password', form=form)

            user.set_password(form.password.data)
            user.reset_token = None
            db.session.commit()
            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('login'))

        return render_template('reset_password.html', title='Reset Password', form=form)
    else:
        flash('Invalid or expired reset token.', 'danger')
        return redirect(url_for('forgot_password'))


def get_user_balance(user_id):
    user = User.query.get(user_id)
    return user.balance if user else None

@app.route('/my_account', methods=['GET', 'POST'])
@login_required
def my_account():
    profile_form = ProfileUpdateForm()
    balance = get_user_balance(current_user.id)

    if profile_form.validate_on_submit():
        # Process form submission (update user profile, etc.)
        current_user.first_name = profile_form.first_name.data
        current_user.last_name = profile_form.last_name.data
        # Update other fields as needed
        db.session.commit()
        flash('Profile updated successfully!', 'success')

    # Retrieve the user's balance
    balance = current_user.balance

    return render_template('my_account.html', profile_form=profile_form, balance=balance)


if __name__ == '__main__':
    app.run(debug=False)
