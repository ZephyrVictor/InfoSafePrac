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
    swagger = Swagger(app)

    app.config.from_object('app.setting')
    app.config.from_object('app.secure')
    app.config['JWT_SECRET_KEY'] = 'ssssseeeeeffffff/sdfsadf^&*KKKKKL*(*(*))'  # 用于加密JWT的密钥

    # 初始化JWTManager
    jwt = JWTManager(app)

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
    from app.web import web
    app.register_blueprint(web)
