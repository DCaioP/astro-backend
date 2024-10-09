from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

config = {
    "MAIL_SERVER": "smtp.gmail.com",
    "MAIL_PORT": 465,
    "MAIL_USE_TSL": True,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": "caio@brainx.dev",
    "MAIL_PASSWORD": ";askdf;lkajsdf",
    "MAIL_DEFAULT_SENDER": "Caio Pontes"
}

app = Flask(__name__)
app.config.update(config)
mail = Mail(app)

db = SQLAlchemy(app)
login_manager = LoginManager()

def create_app():
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://caiop:asdf@127.0.0.1:5432/astro"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "secret"

    db.init_app(app)
    login_manager.init_app(app)

    from app import routes
    routes.init_app(app)

    return app
