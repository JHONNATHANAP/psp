import os


class BaseConfig(object):
    # postgresql://<nombre_usuario>:<password>@<host>:<puerto>/<nombre_basededatos>
    _db_host = os.environ.get("DB_HOST", default=None)
    _db_port = os.environ.get("DB_PORT", default=None)
    _db_user = os.environ.get("DB_USER", default=None)
    _db_password = os.environ.get("DB_PASSWORD", default=None)
    _db_name = os.environ.get("DB_NAME", default=None)
    if _db_host != None and _db_port != None and _db_user != None and _db_password != None and _db_name != None:
        SQLALCHEMY_DATABASE_URI = 'postgresql://'+_db_user+':' + \
            _db_password+'@'+_db_host+':'+_db_port+'/'+_db_name
    
  
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'frase-secreta'
    PROPAGATE_EXCEPTIONS = True
    DEBUG_MODE=False
    DEPLOY_MODE=False
    PATH_TEMPORAL= os.environ.get("PYTHONPATH", default=None)+'Temporal'


class GCPConfig(BaseConfig):
    JWT_SECRET_KEY = 'frase-secreta'

class localWithDocker(BaseConfig):
    DEBUG_MODE=True
    DEPLOY_MODE=True

class localWithoutDocker(BaseConfig):
    DEBUG_MODE=True
    DEPLOY_MODE=False
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost:5432/users'
