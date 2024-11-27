# encoding=utf-8
__author__ = 'Zephyr369'

from flasgger import Swagger
from flask import Flask, url_for
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from werkzeug.utils import redirect

from app.models.base import db
from app.utils.Logger import WebLogger
import requests
import os


login_manager = LoginManager()
mail = Mail()
logger = WebLogger()
# 限制访问频率
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Your API",
        "description": "API for your application",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}


def create_app():
    app = Flask(__name__)
    # 要用来做jwt
    swagger = Swagger(app, template=swagger_template)

    app.config.from_object('app.setting')
    app.config.from_object('app.secure')
    app.config['JWT_SECRET_KEY'] = 'ssssseeeeeffffff/sdfsadf^&*KKKKKL*(*(*))'  # 用于加密JWT的密钥
    app.config['aes_key'] = bytearray(b'\xa1\xd9\xa7\xb3\x9d\x84\x0e\xe2\x98\xf1\xba\xd2\xb8\x18\x7f\x92\xb0\x87\x03\xfc\xa7\xc9\xf8\xec\xb2\x8b\xf3\xf8\x4d\x83\x1e\x4a')

    # 初始化JWTManager
    jwt = JWTManager(app)

    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # 启用 CSRF 保护
    app.config['JWT_COOKIE_SECURE'] = False  # 使用 HTTPS 时应设为 True
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
    app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'csrftoken'  # 设置 CSRF 令牌的 Cookie 名称
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制上传文件大小为 16MB

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        from app.models.ShopUser import ShopUser
        identity = jwt_data["sub"]
        user_type = jwt_data.get("user_type")
        if user_type == 'shop':
            return ShopUser.query.get(identity)
        else:
            return None

    register_blueprint(app)

    db.init_app(app)
    db.create_all(app=app)
    migrate = Migrate(app, db)

    login_manager.init_app(app)
    login_manager.login_view = 'web.auth.login'
    login_manager.login_message = '请先登录或注册'
    mail.init_app(app)
    limiter.init_app(app)

    return app


def register_blueprint(app):
    from app.web import web_bp
    app.register_blueprint(web_bp)

    @app.route('/')
    def default_route():
        return redirect(url_for('web.shop.index'))  # 跳转到商城主界面
