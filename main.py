from flask import jsonify
from flask_restful import Api
from app.resources import ModelUser
from app.resources import UsersModel
from app.resources import UserLogin
from app.resources import UserLogout
from flask_jwt_extended import JWTManager
from app import create_app

app = create_app()
api = Api(app)
jwt = JWTManager(app)


@jwt.revoked_token_loader
def token_de_acesso_invalidado(jwt_header, jwt_payload):
    return jsonify({'message': 'Você saiu do sistema.'}), 401  # unauthorized


api.add_resource(ModelUser, '/user_api')
api.add_resource(UsersModel, '/user_api/<string:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')

if __name__ == "__main__":
    app.run(debug=True)