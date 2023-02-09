import os
from flask import Flask
from src.views.views import ViewLogIn,ViewUser,ViewSignUp,ViewTareas,ViewCruzarGenerico

def create_app(config_name):
        _deployed_env_ = os.environ.get("ENVIRONMENT", default=None)
        app = Flask(__name__)
        print('_deployed_env_='+str(_deployed_env_))
        if(_deployed_env_==None):
                app.config.from_object('src.configuration.BaseConfig')
        elif (_deployed_env_ == 'gcp'):
                app.config.from_object('src.configuration.GCPConfig')
        elif (_deployed_env_ == 'local-with-docker'):
                app.config.from_object('src.configuration.localWithDocker')
        elif (_deployed_env_ == 'local-withouth-docker'):
                app.config.from_object('src.configuration.localWithoutDocker')
        else:
                app.config.from_object('src.configuration.BaseConfig')
     
       ## print(app.config['SQLALCHEMY_DATABASE_URI'])
        return app

def buildResources(api):
    api.add_resource(ViewLogIn, '/auth')
    api.add_resource(ViewSignUp, '/users')
    api.add_resource(ViewUser, '/users/me')
    api.add_resource(ViewTareas, '/tareas')
    api.add_resource(ViewCruzarGenerico, '/merge')