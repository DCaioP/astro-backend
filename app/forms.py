from flask_wtf import FlaskForm
from wtforms.fields import EmailField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.fields.simple import StringField
from wtforms.validators import Length, DataRequired


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email')
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    account_type = SelectField('Account Type', choices=[('business', 'Business'), ('personal', 'Personal')], validators=[DataRequired()])
    submit = SubmitField('Register')
class LoginForm(FlaskForm):
    email = EmailField("Email")
    password = PasswordField("Password", validators=[
        Length(6, 16, "O campo deve conter entre 6 a 16 caracteres.")
    ])
    remember = BooleanField("Permanecer Conectado")
    submit = SubmitField("Entrar")