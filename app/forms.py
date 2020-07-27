from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
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
    receive_email = BooleanField('Get email notifications of announcements from the application. You can change the settings in your profile later on.', default=True)
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is taken. Please choose a different username.')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('This email is already connected to an account.')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password',validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')


class SearchPlanForm(FlaskForm):
    category = SelectField('Category',
                           choices=[("placeholder", "Select Category"),
                                    ("kw1", "General Aid"),
                                    ("kw2", "Disability Aid"),
                                    ("kw3", "Elderly Aid"),
                                    ("kw4", "Childcare Aid"),
                                    ("kw5", "Healthcare Aid")])
    submit = SubmitField('Search')

class InsertPlanForm(FlaskForm):
    name = TextAreaField('Name', validators=[DataRequired()])
    req_short = TextAreaField('Requirements Summarised', validators=[DataRequired()])
    req_full = TextAreaField('Requirements Full', validators=[DataRequired()])
    benefits_short = TextAreaField('Benefits Summarised', validators=[DataRequired()])
    benefits_full = TextAreaField('Benefits Full', validators=[DataRequired()])
    application = TextAreaField('Application', validators=[DataRequired()])
    website = StringField('Website link', validators=[DataRequired()])
    # PLAN KEYWORDS
    # kw1 = General Aid
    # kw2 = Disability Aid
    # kw3 = Elderly Aid
    # kw4 = Childcare
    # kw5 = Healthcare
    kw1 = BooleanField('General Aid')
    kw2 = BooleanField('Disability Aid')
    kw3 = BooleanField('Elderly Aid')
    kw4 = BooleanField('Childcare Aid')
    kw5 = BooleanField('Healthcare Aid')
    submit = SubmitField('Add Plan')


class UpdatePlanForm(FlaskForm):
    name = TextAreaField('Name', validators=[DataRequired()])
    req_short = TextAreaField('Requirements Summarised', validators=[DataRequired()])
    req_full = TextAreaField('Requirements Full', validators=[DataRequired()])
    benefits_short = TextAreaField('Benefits Summarised', validators=[DataRequired()])
    benefits_full = TextAreaField('Benefits Full', validators=[DataRequired()])
    application = TextAreaField('Application', validators=[DataRequired()])
    website = StringField('Website link', validators=[DataRequired()])
    # PLAN KEYWORDS
    # kw1 = General Aid
    # kw2 = Disability Aid
    # kw3 = Elderly Aid
    # kw4 = Childcare
    # kw5 = Healthcare
    kw1 = BooleanField('General Aid')
    kw2 = BooleanField('Disability Aid')
    kw3 = BooleanField('Elderly Aid')
    kw4 = BooleanField('Childcare')
    kw5 = BooleanField('Healthcare')
    submit = SubmitField('Update')


class SendMailForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Send')


class EmailPreferencesForm(FlaskForm):
    receive_email = BooleanField('Notify me of announcements from the application.')
    submit = SubmitField('Update Preferences')
