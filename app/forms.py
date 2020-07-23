from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from app.models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email is None:
            raise ValidationError('There is no account with that email.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message="Passwords do not match.")])
    receive_email = BooleanField('Get email notifications of announcements from the application.', default='checked')
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is taken. Please choose a different username.')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('This email is already connected to an account.')


class SearchPlanForm(FlaskForm):
    kw1 = BooleanField('Childcare')
    kw2 = BooleanField('Disability Aid')
    kw3 = BooleanField('Elderly Aid')
    kw4 = BooleanField('HDB')
    kw5 = BooleanField('Healthcare')
    kw6 = BooleanField('Low Income Aid')
    submit = SubmitField('Submit')


class InsertPlanForm(FlaskForm):
    name = TextAreaField('Name', validators=[DataRequired()])
    req_short = TextAreaField('Requirements Summarised', validators=[DataRequired()])
    req_full = TextAreaField('Requirements Full', validators=[DataRequired()])
    benefits_short = TextAreaField('Benefits Summarised', validators=[DataRequired()])
    benefits_full = TextAreaField('Benefits Full', validators=[DataRequired()])
    application = TextAreaField('Application', validators=[DataRequired()])
    website = StringField('Website link', validators=[DataRequired()])
    # PLAN KEYWORDS
    # kw1 = Childcare
    # kw2 = Disability Aid
    # kw3 = Elderly Aid
    # kw4 = HDB
    # kw5 = Healthcare
    # kw6 = Low Income Aid
    kw1 = BooleanField('Childcare')
    kw2 = BooleanField('Disability Aid')
    kw3 = BooleanField('Elderly Aid')
    kw4 = BooleanField('HDB')
    kw5 = BooleanField('Healthcare')
    kw6 = BooleanField('Low Income Aid')
    submit = SubmitField('Submit')


class SendMailForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Send')
