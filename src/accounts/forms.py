from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, EqualTo, Length, InputRequired, Regexp, Email

from src.accounts.models import User


class RegisterForm(FlaskForm):
    email =EmailField(
        "Email", validators=[DataRequired(), Length(max=120)]
    )
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=6, max=40)]
    )
    password = PasswordField(
        "Password", validators=[
            DataRequired(),
            Length(min=6, max=25),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one symbol"
            )
        ]
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )

    def validate(self, extra_validators):
        initial_validation = super(RegisterForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered")
            return False
        email_user = User.query.filter_by(email=self.email.data).first()
        if email_user:
            self.email.errors.append("Email already registered")
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append("Passwords must match")
            return False
        return True


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
                      InputRequired(), Length(min=6, max=6)])
    
class ForgotForm(FlaskForm):
    email = EmailField('Email Address', validators=[DataRequired(), Email()])

class PasswordResetForm(FlaskForm):
    new_password = PasswordField("New Password", validators=[
        DataRequired(),
        Length(min=6, max=25),
        Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
            message="Password must contain at least one uppercase letter, one lowercase letter, one number, and one symbol"
        )
    ])
