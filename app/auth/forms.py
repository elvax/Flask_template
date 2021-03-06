from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms import ValidationError
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from ..models import User


class LoginForm(FlaskForm):
    username = StringField('Email', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    # token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')


class OtpForm(FlaskForm):
    token = StringField('Token', validators=[DataRequired(), Length(6, 6)])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log in')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1,64), Email()])
    username = StringField('Username', validators=[DataRequired(),
                                                    Length(1, 64),
                                                    Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                       'Usernames must have only letters, '
                                                        'numbers, dots or underscores')
                                                   ])
    password = PasswordField('Password', validators=[DataRequired(),
                                                     EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    enable_2fa = BooleanField('Enable two factor authentication')
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')