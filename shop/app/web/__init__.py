# encoding=utf-8
__author__ = 'Zephyr369'

from flask import Blueprint, jsonify


web_bp = Blueprint('web', __name__)


@web_bp.errorhandler(404)
def not_found(e):
    return jsonify({"result": "Page Not Found"})


# 在这里import编写的视图函数文件
from app.web.auth import auth_bp
# from app.web.bank_auth import bank_auth_bp
from app.web.shop import shop_bp
web_bp.register_blueprint(auth_bp, url_prefix='/auth')
# web_bp.register_blueprint(bank_auth_bp, url_prefix='/bank_auth')
web_bp.register_blueprint(shop_bp, url_prefix='/shop')