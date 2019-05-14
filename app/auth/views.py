from flask import render_template, request, url_for, flash, redirect, session, abort
from flask_login import login_user, login_required, logout_user
import pyqrcode
from io import BytesIO
from . import auth
from .forms import LoginForm, RegistrationForm, OtpForm
from ..models import User
from .. import db


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            # user.verify_totp(form.token.data)
            if user.enabled_2fauth:
                session['username'] = user.username
                return redirect(url_for('auth.check_otp'))
            else:
                login_user(user, form.remember_me.data)
                next = request.args.get('next')
                if next is None or not next.startswith('/'):
                    next = url_for('main.index')
                return redirect(next)
        flash('Invalid username, password or token')
    return render_template('auth/login.html', form=form)

@auth.route('/check-otp', methods=['GET', 'POST'])
def check_otp():
    if 'username' not in session:
        return redirect(url_for('main.index'))

    form = OtpForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=session['username']).first()
        if user is None:
            return redirect(url_for('index'))

        if user.enabled_2fauth and user.verify_totp(form.token.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid token')

    return render_template('auth/check-otp.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('main.index'))


# noinspection PyArgumentList
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.email.data,
                    password=form.password.data,
                    enabled_2fauth=form.enable_2fa.data)
        db.session.add(user)
        db.session.commit()

        if form.enable_2fa.data:
            session['username'] = user.username
            return redirect(url_for('auth.twofactor'))
        else:
            return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/twofactor')
def twofactor():
    if 'username' not in session:
        return redirect(url_for('main.index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    # do not cache
    return render_template('auth/two-factor.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@auth.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    del session['username']

    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=5)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}