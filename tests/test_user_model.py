import unittest

from app import create_app, db
from app.models import User


class UserModelTestCase(unittest.TestCase):

    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        u = User(password='pass')
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password='pass')
        with self.assertRaises(AttributeError):
            _ = u.password

    def test_password_verification(self):
        u = User(password='pass')
        self.assertTrue(u.verify_password('pass'))
        self.assertFalse(u.verify_password('p'))

    def test_password_salts_are_random(self):
        u = User(password='pass')
        u2 = User(password='pass')
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_otp_token_created(self):
        u = User(enabled_2fauth=True)
        self.assertTrue(u.otp_secret is not None)