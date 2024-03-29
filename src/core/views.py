from flask import Blueprint, render_template, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from .forms import PasswordForm, GeneratePasswordForm
from src import db
from .models import Password
from datetime import datetime


core_bp = Blueprint("core", __name__)


@core_bp.route("/")
@login_required
def home():
    form = PasswordForm()
    return render_template("core/password-manager.html", form=form)


@core_bp.route('/password-manager', methods=['GET', 'POST'])
@login_required
def password_manager():
    # Initialize forms for adding a new password and generating a password
    form = PasswordForm()
    generate_form = GeneratePasswordForm()

    # Retrieve passwords associated with the current user's email
    passwords = Password.query.filter_by(user_email=current_user.email).all()

    # Check if the form for adding a new password is submitted and valid
    if form.validate_on_submit():
        # Extract data from the form
        website = form.website.data
        password = form.password.data
        # remember = form.remember.data

        # Check if a password already exists for the given website and user's email
        existing_password = Password.query.filter_by(website=website, user_email=current_user.email).first()
        if existing_password:   
            # If a password exists, update it with the new password
            existing_password.encrypted_password = existing_password.encrypt_password(password)
            existing_password.last_updated = datetime.utcnow()
            db.session.commit()
            flash('Password updated successfully!', 'success')
        else:
            # If no password exists, create a new one associated with the current user's email
            new_password = Password(website=website, password=password, user_email=current_user.email)
            db.session.add(new_password)
            db.session.commit()
            flash('Password added successfully!', 'success')

        # Redirect to the password manager page to display the updated list of passwords
        return redirect(url_for('core.password_manager'))

    # If the form is not submitted or is not valid, render the password manager page
    # and pass the forms and passwords to the template
    return render_template('core/password-manager.html', form=form, generate_form=generate_form, passwords=passwords)


@core_bp.route('/delete-password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)
    db.session.delete(password)
    db.session.commit()
    flash('Password deleted successfully!', 'success')
    return redirect(url_for('core.password_manager'))

@core_bp.route('/check-password-expiration/<int:password_id>', methods=['GET'])
@login_required
def check_password_expiration(password_id):
    password = Password.query.get_or_404(password_id)
    expired = password.is_expired()
    return jsonify({'expired': expired})
