# encoding=utf-8
__author__ = 'Zephyr369'
from flask import Blueprint, jsonify

web = Blueprint('web',__name__)

@web.app.errorhandler(404)
def not_found(e):
    return jsonify({"result":"Page Not Found"})

# 在这里import编写的视图函数文件