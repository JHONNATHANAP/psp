
from src.views.views import ViewLogIn, ViewUser, ViewSignUp, ViewPing
from datetime import date, datetime, timedelta
from src import create_app, buildResources
import logging
import pytest
from src.models.models import db, User
from flask_restful import Api
import hashlib
import bcrypt
from flask_jwt_extended import JWTManager
from faker import Faker
from flask_jwt_extended import create_access_token

@pytest.fixture
def app():
    """Create application for the tests."""
    _app = create_app('default')
    _app.logger.setLevel(logging.CRITICAL)
    ctx = _app.test_request_context()
    ctx.push()

    _app.config["TESTING"] = True
    _app.testing = True
    _app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
    print(_app.config["SQLALCHEMY_DATABASE_URI"])
    with _app.app_context():
        db.init_app(_app)
        db.create_all()

    api = Api(_app)
    buildResources(api)
    jwt = JWTManager(_app)

    yield _app
    ctx.pop()
    return _app


@pytest.fixture
def client(app):
    client = app.test_client()
    yield client


@pytest.fixture
def base_data(app):
    data = []
    fake = Faker()
    for x in range(10):
        email = fake.email()
        username = fake.user_name()
        email = fake.email()
        password = fake.password(length=12)
        expires_delta = timedelta(minutes=25)
        token = create_access_token(identity={
                                        'id':x ,'username': username, 'email': email}, expires_delta=expires_delta)
        data.append(
            {"email": email, "username": username, "password": password,"token":token})

        salt = bcrypt.gensalt().decode()
        salted_password = password + salt
        hashlib_password = hashlib.sha256(
            salted_password.encode()).hexdigest()

            
        user = User(username=username, email=email, password=hashlib_password,
                    salt=salt, token=token, expireAt=datetime.now(), createdAt=datetime.now()+expires_delta)
        db.session.add(user)
        db.session.commit()

    yield data
