# encoding=utf-8
__author__ = 'Zephyr369'

from flask import Blueprint, jsonify

web = Blueprint('web', __name__)


@web.errorhandler(404)
def not_found(e):
    return jsonify({"result": "Page Not Found"})


# 在这里import编写的视图函数文件
from app.web import auth, bank, admin, store, user

web.register_blueprint(auth.web)
web.register_blueprint(bank.web, url_prefix='/bank')
web.register_blueprint(admin.web, url_prefix='/admin')
web.register_blueprint(store.web, url_prefix='/store')
web.register_blueprint(user.web, url_prefix='/user')
