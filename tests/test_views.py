
from unittest import TestCase
from faker import Faker
import json


def test_login_200(client, base_data) -> None:

    for x in base_data:
        user = {
            "username": x["username"],
            "password": x["password"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/auth",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 200
        assert respuesta["id"] != None
        assert respuesta["token"] != None
        assert respuesta["expireAt"] != None


def test_login_400_password(client, base_data) -> None:

    for x in base_data:
        user = {
            "username": x["username"],
            # "password": x["password"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/auth",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 400
        assert "No se encuentra el campo:password." in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_login_400_username(client, base_data) -> None:

    for x in base_data:
        user = {
            # "username": x["username"],
            "password": x["password"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/auth",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 400
        assert "No se encuentra el campo:username." in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_login_404_username_invalid(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username": fake.user_name(),
            "password": x["password"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/auth",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 404
        assert "El usuario o contraseña son incorrectos" in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_login_404_password_invalid(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username": x["username"],
            "password": fake.password(length=12)
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/auth",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 404
        assert "El usuario o contraseña son incorrectos" in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_signup_201(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username":  fake.user_name(),
            "password": fake.password(length=10, special_chars=False, digits=True, upper_case=True, lower_case=True)+"!",
            "email": fake.email()
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/users",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 201
        assert respuesta["id"] != None
        assert respuesta["createdAt"] != None


def test_signup_412_user_exist_by_username(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username":  x["username"],
            "password": fake.password(length=10, special_chars=False, digits=True, upper_case=True, lower_case=True)+"!",
            "email": fake.email()
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/users",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 412
        assert "El usuario ingresado ya existe" in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_signup_412_user_exist_by_email(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username":  fake.user_name(),
            "password": fake.password(length=10, special_chars=False, digits=True, upper_case=True, lower_case=True)+"!",
            "email": x["email"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/users",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 412
        assert "El usuario ingresado ya existe" in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_signup_400_username(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            # "username":  fake.user_name(),
            "password": fake.password(length=10, special_chars=False, digits=True, upper_case=True, lower_case=True)+"!",
            "email": x["email"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/users",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 400
        assert "No se encuentra el campo:username." in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_signup_400_password(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username":  fake.user_name(),
            # "password": fake.password(length=10, special_chars=False, digits=True, upper_case=True, lower_case=True)+"!",
            "email": x["email"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/users",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 400
        assert "No se encuentra el campo:password." in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_signup_400_email(client, base_data) -> None:

    fake = Faker()
    for x in base_data:
        user = {
            "username":  fake.user_name(),
            "password": fake.password(length=10, special_chars=False, digits=True, upper_case=True, lower_case=True)+"!",
            # "email": x["email"]
        }
        headers = {'Content-Type': 'application/json'}
        solicitud_users = client.post("/users",
                                      data=json.dumps(user),
                                      headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 400
        assert "No se encuentra el campo:email." in respuesta["mensaje"]
        assert respuesta["error"] == True


def test_user_info_200(client, base_data) -> None:

    for x in base_data:

        headers = {'Content-Type': 'application/json',
                   "Authorization": "Bearer "+x["token"]}
        solicitud_users = client.get("/users/me",
                                     headers=headers)
        respuesta = json.loads(solicitud_users.get_data())
        print(respuesta)
        assert solicitud_users.status_code == 200
        assert respuesta["id"] != None
        assert respuesta["username"] == x["username"]
        assert respuesta["email"] == x["email"]

def test_user_info_400(client, base_data) -> None:  

    headers = {'Content-Type': 'application/json'}
    solicitud_users = client.get("/users/me",
                                    headers=headers)
    respuesta = json.loads(solicitud_users.get_data())
    print(respuesta)
    assert solicitud_users.status_code == 401


def test_user_info_401(client, base_data) -> None:
    fake = Faker()

    headers = {'Content-Type': 'application/json',"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY3NTEzNTMzMiwianRpIjoiZjZhZjBjNDUtYTA3MS00MTcyLTliYjAtOTk2OTc0ZDAzMjNkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6eyJpZCI6MSwidXNlcm5hbWUiOiJKaG9uIiwiZW1haWwiOiJpbmdlLmpob25hcEBnbWFpbC5jb20ifSwibmJmIjoxNjc1MTM1MzMyLCJleHAiOjE2NzUxMzY4MzJ9.-OSJ71TJ1N49zo2_Ndv3EYuxdf2N5Xrfsz3uN1sPhAk"}
    solicitud_users = client.get("/users/me",
                                    headers=headers)
    respuesta = json.loads(solicitud_users.get_data())
    print(respuesta)
    assert solicitud_users.status_code == 401

def test_ping_200(client, base_data) -> None:
      
    solicitud_users = client.get("/users/ping",)
    respuesta = json.loads(solicitud_users.get_data())
    print(respuesta)
    assert respuesta=='pong'
