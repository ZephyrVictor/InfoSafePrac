# encoding=utf-8
__author__ = 'Zephyr369'

from flask import Blueprint, jsonify

from app.web import admin

web_bp = Blueprint('web', __name__)


@web_bp.errorhandler(404)
def not_found(e):
    return jsonify({"result": "Page Not Found"})


# 在这里import编写的视图函数文件
from app.web.auth import auth_bp
# from app.web.bank_auth import bank_auth_bp
from app.web.bank import bank_bp
from app.web.store import store_bp
from app.web.user import user_bp
from app.web.admin import admin_bp
web_bp.register_blueprint(auth_bp, url_prefix='/auth')
# web_bp.register_blueprint(bank_auth_bp, url_prefix='/bank_auth')
web_bp.register_blueprint(bank_bp, url_prefix='/bank')
web_bp.register_blueprint(store_bp, url_prefix='/store')
web_bp.register_blueprint(user_bp, url_prefix='/user')
web_bp.register_blueprint(admin_bp, url_prefix='/admin')