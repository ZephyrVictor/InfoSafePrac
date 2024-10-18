# encoding=utf-8
__author__ = 'Zephyr369'

import re

from flask import jsonify, json
from werkzeug.exceptions import BadRequest

from app.forms.auth import RegisterForm
from app.models.User import User
from app.models.base import db


def do_register_form(data: json) -> json:
    form = RegisterForm(data)

    if not form.validate():
        return jsonify({"msg": form.errors}), 400

    # 注册新用户
    new_user = User()
    new_user.set_attrs(data)
    new_user.password = data['password']
    new_user.payPassword = data['payPassword']  # 使用表单中的支付密码

    db.session.add(new_user)
    db.session.commit()

    # 生成 JWT 和 Cookie
    access_token = new_user.generate_jwt(new_user, False)
    response = jsonify({"msg": "注册成功", "access_token": access_token})
    response.set_cookie(
        'access_token',
        access_token,
        httponly=True,
        secure=True,
        samesite='Lax',
        max_age=60 * 60 * 24
    )

    return response, 201
