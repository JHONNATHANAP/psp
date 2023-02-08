import glob
import hashlib
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path

import bcrypt
import jwt
import pandas as pd
from flask import current_app, request, send_file
from flask_jwt_extended import create_access_token, jwt_required
from flask_restful import Resource

from src.models.models import User, UserSchema, db

user_schema = UserSchema()


class ViewTareas(Resource):
    def post(self):
        # diabetes_file = request['args']['files']
        try:      

            json_diabetes = file_to_dict(request.files.get("Diabetes"))
            json_praluent = file_to_dict(request.files.get("Praluent"))
            json_base = file_to_dict(request.files.get("Base"))
            json_producto = file_to_dict(request.files.get("Producto"))
            json_cargos = file_to_dict(request.files.get("Cargos"))

            json_base['Número caso producto'] = []
            json_base['Número caso programa'] = []
            json_base['Cargo'] = []
            json_base['Zona'] = []
            for x in range(len(json_base['Relacionado con'])):
                # print(json_base['Relacionado con'][x])
                id_base = int(
                    json_base['Relacionado con'][x]) if json_base['Relacionado con'][x].isnumeric() else -1

                numero_producto = json_diabetes['Número de caso principal'][json_diabetes['Número del caso'].index(
                    id_base)] if id_base in json_diabetes['Número del caso'] else ""

                numero_programa = json_producto['Programa'][json_producto['Número del caso'].index(round(
                    numero_producto, 1))] if numero_producto in json_producto['Número del caso'] else json_praluent['Programa'][json_praluent['Número del caso'].index(id_base)] if id_base in json_praluent['Número del caso'] else ""

                cargo = json_cargos['Cargo'][json_cargos['Asignado'].index(
                    json_base["Asignado"][x])] if json_base["Asignado"][x] in json_cargos["Asignado"] else ""
                zona = json_cargos['Zona'][json_cargos['Asignado'].index(
                    json_base["Asignado"][x])] if json_base["Asignado"][x] in json_cargos["Asignado"] else ""

                json_base['Número caso programa'].append(numero_programa)
                json_base['Número caso producto'].append(numero_producto)
                json_base['Cargo'].append(cargo)
                json_base['Zona'].append(zona)
            
            
            path_storage = current_app.config['PATH_TEMPORAL']
            df = pd.DataFrame(data=json_base)
            df.to_excel(path_storage+"/tareas.xlsx", index=False)

            response = send_file(
                os.path.join(path_storage,"tareas.xlsx"), as_attachment=True)
            # os.remove(input_path)
            for f in os.listdir(path_storage):
                os.remove(os.path.join(path_storage, f))
            return response
        except Exception as e:
            return {"mensaje": "Hubo un error no esperado. "+str(e), "error": True}, 500


def file_to_dict(file):

    path_storage = current_app.config['PATH_TEMPORAL']
    path_file = os.path.join(path_storage, file.filename)

    file.save(path_file)

    file_path = Path(path_file)
    file_extension = file_path.suffix.lower()[1:]

    return excel_converter(path_file)


def excel_converter(path_file, type='html'):
    valid_types = ['html', 'xlsx', 'xls']
    dict_type = 'list'
    if type not in valid_types:
        return 'error'

    try:

        if type == "html":
            df = pd.read_html(path_file)
            return df[0].to_dict(orient=dict_type)
        else:
            df = pd.read_excel(
                path_file,
                engine='openpyxl'
            )
            return df.to_dict(orient=dict_type)
    except:
        new_try_index = valid_types.index(type)+1
        if (new_try_index >= len(valid_types)):
            return "error"
        else:
            try_with = valid_types[new_try_index]

            return excel_converter(path_file, try_with)


class UserService:
    def __init__(self, _session=None) -> None:
        self.session = _session or db.session

    def _get_user_by_username(self, u_username) -> User:
        return User.query.filter_by(
            username=u_username).first()


class ViewLogIn(Resource):
    def __init__(self, _session=None) -> None:
        self.session = _session or db.session

    def _get_user_by_username(self, u_username) -> User:
        return User.query.filter_by(
            username=u_username).first()

    def post(self):
        try:
            validacionDeCampos = validarSiCampoExiste(
                request.json, ['username', 'password'])

            if (validacionDeCampos['isValid'] == False):
                return {'mensaje': validacionDeCampos['mensaje'], 'error': True}, 400
            u_username = request.json['username']
            u_password = request.json['password']

            user = self._get_user_by_username(u_username)
            # print(user.salt,user.username,user.password,'--------------',u_username,u_password)
            if not user:
                return {'mensaje': 'El usuario o contraseña son incorrectos', 'error': True}, 404

            salt = user.salt
            salted_password = u_password + salt
            hashlib_password = hashlib.sha256(
                salted_password.encode()).hexdigest()
            if hashlib_password != user.password:
                return {'mensaje': 'El usuario o contraseña son incorrectos', 'error': True}, 404

            expires_delta = timedelta(minutes=25)
            token = create_access_token(identity={
                                        'id': user.id, 'username': u_username, 'email': user.email}, expires_delta=expires_delta)
            today = datetime.now()
            iso_date = today.isoformat()
            user.token = token
            user.expireAt = today+expires_delta
            self.session.commit()
            return {'id': user.id, 'expireAt': iso_date, 'token': token, 'mensaje': 'Token generado con exito', "error": False}, 200

        except Exception as e:
            return {"mensaje": "Hubo un error no esperado. "+str(e), "error": True}, 500


class ViewSignUp(Resource):
    @jwt_required()
    def get(self):
        return [user_schema.dump(user) for user in User.query.all()]

    def post(self):

        try:
            validacionDeCampos = validarSiCampoExiste(
                request.json, ['email', 'username', 'password'])

            if (validacionDeCampos['isValid'] == False):
                return {'mensaje': validacionDeCampos['mensaje'], 'error': True}, 400

            u_username = request.json['username']
            u_password = request.json['password']
            u_email = request.json['email']

            if not (checkUserName(request.json['username'])):
                return {'mensaje': 'El username no cumple con lo requerido:Mínimo 4 caracteres y máximo 32 caracteres. Solo puede incluir letras A-Z a-z y números 0-9. Sin espacios.', 'error': True}, 412
            if not (checkEmail(request.json['email'])):
                return {'mensaje': 'Email invalido'}, 412
            if not passwordCheck(request.json['password']):
                return {'mensaje': 'La contraseña no cumple con lo requerido:Mínimo 8 caracteres y máximo 16 caracteres. Mínimo 1 mayúscula A-Z. Mínimo 1 minúscula a-z, Mínimo 1 número 0-9. Mínimo 1 caracter especial @#$%^&+= ', 'error': True}, 412

            user = User.query.filter(User.username.ilike(
                u_username) | User.email.ilike(u_email)).first()
            if user:
                return {'mensaje': 'El usuario ingresado ya existe', 'error': True}, 412

            salt = bcrypt.gensalt().decode()
            salted_password = u_password + salt
            hashlib_password = hashlib.sha256(
                salted_password.encode()).hexdigest()
            expires_delta = timedelta(minutes=25)
            today = datetime.now()
            iso_date = today.isoformat()

            new_user = User(
                username=u_username, email=u_email, password=hashlib_password, salt=salt, token='', expireAt=today+expires_delta, createdAt=today)
            db.session.add(new_user)
            db.session.commit()
            token = create_access_token(identity={
                                        'id': new_user.id, 'username': u_username, 'email': new_user.email}, expires_delta=expires_delta)
            new_user.token = token
            db.session.commit()
            return {'id': new_user.id, 'createdAt': iso_date, 'mensaje': 'Usuario creado con exito', "error": False}, 201
        except Exception as e:
            return {"mensaje": "Hubo un error no esperado. "+str(e), "error": True}, 500


class ViewUser(Resource):
    @jwt_required()
    def get(self):
        try:
            token_data = getTokenData(request)
            return token_data['sub'], 200

        except Exception as e:
            return {"mensaje": "Hubo un error no esperado. "+str(e), "error": True}, 500


def validarSiCampoExiste(request, campos):
    cumple = {'isValid': True, 'mensaje': ''}
    for campo in campos:
        if campo not in request:
            cumple['isValid'] = False
            cumple['mensaje'] += 'No se encuentra el campo:'+campo+'. '
    return cumple


def checkUserName(user):
    regex = r'^[a-zA-Z0-9_.-]{4,32}$'
    if (re.match(regex, user)):
        return True
    else:
        return False


def checkEmail(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if (re.fullmatch(regex, email)):
        return True
    else:
        return False


def passwordCheck(password):
    regex = r'[A-Za-z0-9@#$%^&+=!¡¿?]{8,16}'
    if (re.fullmatch(regex, password)):
        return True
    else:
        return False


def getTokenData(request):
    token = request.headers.environ['HTTP_AUTHORIZATION'].split("Bearer ")[1]
    return jwt.decode(token, 'frase-secreta', algorithms=['HS256'])
