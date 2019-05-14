from . import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import base64
import onetimepass
import os


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))
    enabled_2fauth = db.Column(db.Boolean)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if self.enabled_2fauth and self.otp_secret is None:
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/Flask_template:{0}?secret={1}&issuer=Flask_template'\
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def __repr__(self):
        return 'User {} {}'.format(self.id, self.email)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))