

from src import create_app,buildResources
from src.models.models import db
from flask_restful import Api
from flask_jwt_extended import JWTManager

app = create_app('default')
app_context = app.app_context()
app_context.push()
db.init_app(app)
#db.create_all()
api = Api(app)
buildResources(api)
jwt = JWTManager(app)

print('inicio')
if(app.config['DEPLOY_MODE']==True):
    app.run(host='0.0.0.0', port=5001)