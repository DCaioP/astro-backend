from flask_restful import Resource, reqparse
from app.models import User
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

atributos = reqparse.RequestParser()
atributos.add_argument('email', type=str, required=True, help="O campo 'email' nunca deixar em branco.")
atributos.add_argument('password', type=str, required=True, help="O campo 'password' nunca deixar em branco.")


class ModelUser(Resource):
    argumentos = reqparse.RequestParser()
    argumentos.add_argument('user_id')
    argumentos.add_argument('email')
    argumentos.add_argument('name')
    argumentos.add_argument('cpf')
    argumentos.add_argument('address')
    argumentos.add_argument('phone')
    argumentos.add_argument('password')
    argumentos.add_argument('token')

    @jwt_required()
    def get(self):
        return {'Users': [users.json() for users in User.query.all()]}

    @jwt_required()
    def post(self):
        dados = ModelUser.argumentos.parse_args()
        user = User(
            email=dados['email'],
            name=dados['name'],
            cpf=dados['cpf'],
            address=dados['address'],
            phone=dados['phone'],
            password=generate_password_hash(dados['password']),
            token=dados['token']
        )
        db.session.add(user)
        db.session.commit()
        return user.json(), 201


class UsersModel(Resource):
    argumentos = reqparse.RequestParser()
    argumentos.add_argument('user_id')
    argumentos.add_argument('email')
    argumentos.add_argument('name')
    argumentos.add_argument('cpf')
    argumentos.add_argument('address')
    argumentos.add_argument('phone')
    argumentos.add_argument('password')
    argumentos.add_argument('token')

    @jwt_required()
    def get(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if user:
            return user.json()
        return {'message': 'Usuário inexistente'}, 404

    @jwt_required()
    def put(self, user_id):
        dados = UsersModel.argumentos.parse_args()
        user = User(email=dados['email'],
                    name=dados['name'],
                    cpf=dados['cpf'],
                    address=dados['address'],
                    phone=dados['phone'],
                    password=generate_password_hash(dados['password']),
                    token=dados.get('token')
                    )
        user_encontrado = user.query.filter_by(id=user_id).first()
        if user_encontrado:
            user_encontrado.query.filter_by(id=user_id).update(
                {"email": dados['email'], "name": dados['name'], "address": dados['address'], "cpf": dados['cpf'], "password": generate_password_hash(dados['password'])})
            db.session.commit()
            return user_encontrado.json(), 200
        db.session.add(user)
        db.session.commit()
        return user.json(), 201

    @jwt_required()
    def delete(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return {'message': 'Usuário excluido.'}
        return {'message': 'Usuário inexistente'}, 404


class UserLogin(Resource):
    @classmethod
    def post(cls):
        dados = atributos.parse_args()
        user = User.query.filter_by(email=dados['email']).first()
        if user and check_password_hash(user.password, dados['password']):
            token_de_acesso = create_access_token(identity=user.user_id)
            return {'access_token': token_de_acesso}, 200
        return {'Mensagem': 'O email ou password estão incorretos, por favor verifique.'}, 401  # Unauthorized@classmethod


class UserLogout(Resource):

    @jwt_required()
    def post(self):
        jwt_id = get_jwt()['jti']
        BLACKLIST.add(jwt_id)
        return {'Mensagem': 'Usuário deslogado com sucesso!'}, 200