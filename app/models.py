from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Aggregate_data(db.Model):
    __tablename__ = 'aggregate_data'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.date, nullable=False)
    ho = db.Column(db.double_precision, nullable=False)
    ho_acumulado = db.Column(db.double_precision, nullable=False)
    ho_meta_diaria = db.Column(db.double_precision, nullable=False)
    ho_meta_diaria_acumulado = db.Column(db.double_precision, nullable=False)

class User(db.Model, UserMixin  ):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String)
    password = db.Column(db.String, nullable=False)
    date = db.Column(db.Date, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
