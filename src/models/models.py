from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
db = SQLAlchemy()

USER_DB_NAME='user'
CASCADE_FULL_DB = 'all, delete, delete-orphan'

class User(db.Model):
    __tablename__ = USER_DB_NAME
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32))
    email = db.Column(db.String(64))
    password = db.Column(db.String(400))
    salt = db.Column(db.String(400))
    token = db.Column(db.String(400))
    expireAt = db.Column(db.DateTime)
    createdAt = db.Column(db.DateTime)

    __table_args__ = (db.UniqueConstraint('username', 'email', name='unique_user'),)


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_relationships = True
        load_instance = True