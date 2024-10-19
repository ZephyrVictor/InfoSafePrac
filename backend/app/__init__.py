# encoding=utf-8
__author__ = 'Zephyr369'

from flasgger import Swagger
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


from app.models.base import db
from app.utils.Logger import WebLogger

login_manager = LoginManager()
mail = Mail()
logger = WebLogger()
# 限制访问频率
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


def create_app():
    app = Flask(__name__)
    # 要用来做jwt
    swagger = Swagger(app, template={
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
            }
        }
    })

    app.config.from_object('app.setting')
    app.config.from_object('app.secure')
    app.config['JWT_SECRET_KEY'] = 'ssssseeeeeffffff/sdfsadf^&*KKKKKL*(*(*))'  # 用于加密JWT的密钥

    # 初始化JWTManager
    jwt = JWTManager(app)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        from app.models.BankUser import BankUser
        from app.models.ShopUser import ShopUser
        identity = jwt_data["sub"]
        user_type = jwt_data.get("user_type")
        if user_type == 'bank':
            return BankUser.query.get(identity)
        elif user_type == 'shop':
            return ShopUser.query.get(identity)
        else:
            return None

    register_blueprint(app)

    db.init_app(app)
    db.create_all(app=app)

    login_manager.init_app(app)
    login_manager.login_view = 'web.login'
    login_manager.login_message = '请先登录或注册'
    mail.init_app(app)
    limiter.init_app(app)

    return app


def register_blueprint(app):
    from app.web import web_bp
    app.register_blueprint(web_bp)
