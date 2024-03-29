from src.utils import get_b64encoded_qr_image
from .forms import LoginForm, RegisterForm, TwoFactorForm, ForgotForm, PasswordResetForm
from src.accounts.models import User
from src import db, bcrypt, mail
from flask_login import current_user, login_required, login_user, logout_user
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_mail import Message
import uuid


accounts_bp = Blueprint("accounts", __name__)

HOME_URL = "core.password_manager"
SETUP_2FA_URL = "accounts.setup_two_factor_auth"
VERIFY_2FA_URL = "accounts.verify_two_factor_auth"


@accounts_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already registered.", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable first to login.", "info")
            return redirect(url_for(SETUP_2FA_URL))
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        try:
            user = User(email=form.email.data,username=form.username.data, password=form.password.data)
            db.session.add(user)
            db.session.commit()

            login_user(user)
            flash("You are registered. You have to enable 2-Factor Authentication first to login.", "success")

            return redirect(url_for(SETUP_2FA_URL))
        except Exception:
            db.session.rollback()
            flash("Registration failed. Please try again.", "danger")

    return render_template("accounts/register.html", form=form)


@accounts_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_two_factor_authentication_enabled:
            flash("You are already logged in.", "info")
            return redirect(url_for(HOME_URL))
        else:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable first to login.", "info")
            return redirect(url_for(SETUP_2FA_URL))
        
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, request.form["password"]):
            login_user(user)
            if not current_user.is_two_factor_authentication_enabled:
                flash(
                    "You have not enabled 2-Factor Authentication. Please enable first to login.", "info")
                return redirect(url_for(SETUP_2FA_URL))

            return redirect(url_for(VERIFY_2FA_URL))
        elif not user:
            flash("You are not registered. Please register.", "danger")
        else:
            flash("Invalid email and/or password.", "danger")
    return render_template("accounts/login.html", form=form)


@accounts_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You were logged out.", "success")
    return redirect(url_for("accounts.login"))


@accounts_bp.route("/setup-2fa")
@login_required
def setup_two_factor_auth():
    secret = current_user.secret_token
    uri = current_user.get_authentication_setup_uri()
    base64_qr_image = get_b64encoded_qr_image(uri)
    return render_template("accounts/setup-2fa.html", secret=secret, qr_image=base64_qr_image)


@accounts_bp.route("/verify-2fa", methods=["GET", "POST"])
@login_required
def verify_two_factor_auth():
    form = TwoFactorForm(request.form)
    if form.validate_on_submit():
        if current_user.is_otp_valid(form.otp.data):
            if current_user.is_two_factor_authentication_enabled:
                flash("2FA verification successful. You are logged in!", "success")
                return redirect(url_for(HOME_URL))
            else:
                try:
                    current_user.is_two_factor_authentication_enabled = True
                    db.session.commit()
                    flash("2FA setup successful. You are logged in!", "success")
                    return redirect(url_for(HOME_URL))
                except Exception:
                    db.session.rollback()
                    flash("2FA setup failed. Please try again.", "danger")
                    return redirect(url_for(VERIFY_2FA_URL))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            return redirect(url_for(VERIFY_2FA_URL))
    else:
        if not current_user.is_two_factor_authentication_enabled:
            flash(
                "You have not enabled 2-Factor Authentication. Please enable it first.", "info")
        return render_template("accounts/verify-2fa.html", form=form)
    


@accounts_bp.route("/forgot", methods=["GET", "POST"])
def forgot():
    form = ForgotForm()
    Message = None  # Initialize Message variable
    if form.validate_on_submit():
        # Query the user with the provided email
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            # Generate a unique code for password reset
            code = str(uuid.uuid4())
            # Update user's configuration with the password reset code
            user.change_configuration = {"password_reset_code": code}
            # Save changes to the database
            db.session.commit() 

            # Email the user with the password reset link
           # Email the user with the password reset link
            subject = "Password Reset Request"
            html_body = f'''
            <p>We have received a request to reset your password.</p>
            <p>To reset your password, please click on this link:</p>
            <p><a href="http://localhost:5000/password_reset/{user.username}/{code}">Reset Password</a></p>
            '''

            text_body = f'''
            We have received a request to reset your password.
            To reset your password, please visit the following link:
            http://localhost:5000/password_reset/{user.username}/{code}
            '''

            email(user.email, subject, html_body, text_body)  


            flash ("You will receive a password reset email", "success")
        else:
            flash ("No user found with that email address", "danger")
    else:
        Message = "Error validation"
    return render_template("accounts/forgot_password.html", form=form, Message=Message)

# Function to send email
def email(recipients, subject, html_body, text_body):
    msg = Message(subject,
                  recipients=[recipients])
    msg.html = html_body
    msg.body = text_body
    mail.send(msg)

from .forms import PasswordResetForm


@accounts_bp.route("/password_reset/<username>/<code>", methods=["GET", "POST"])
def password_reset(username, code):
    # Fetch the user by username
    user = User.query.filter_by(username=username).first()

    # If user not found, handle the error
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("accounts.password_reset_error"))

    # Initialize the password reset form
    form = PasswordResetForm()

    # If the form is submitted and valid
    if form.validate_on_submit():
        # Extract the new password from the form
        new_password = form.new_password.data

        # Update the user's password
        user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")

        # Commit changes to the database
        db.session.commit()

        # Redirect the user to the login page after successful password reset
        flash("Password reset successful. Please login with your new password.", "success")
        return redirect(url_for("accounts.login"))

    # Render the password reset form with the form variable included in the context
    return render_template("accounts/password_reset_form.html", form=form, username=username, code=code)

