from datetime import date

from flask_wtf import FlaskForm
from wtforms import DateField, EmailField, PasswordField, StringField, TimeField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=80)])
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=10, message="Password must be at least 10 characters."),
    ])
    confirm = PasswordField("Confirm password", validators=[
        DataRequired(), EqualTo("password", message="Passwords don't match."),
    ])


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])


class ShiftForm(FlaskForm):
    role = StringField("Role or department", validators=[DataRequired(), Length(max=80)])
    day = DateField("Date", validators=[DataRequired()])
    start_time = TimeField("Start", validators=[DataRequired()])
    end_time = TimeField("End", validators=[DataRequired()])
    note = StringField("Note (optional)", validators=[Length(max=300)])

    def validate_day(self, field):
        if field.data < date.today():
            raise ValidationError("You can't post a shift in the past.")

