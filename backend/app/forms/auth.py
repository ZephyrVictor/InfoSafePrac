# encoding=utf-8
__author__ = 'Zephyr369'

import re

from flask import jsonify
# 这些等等 打算放到前端校验
# 2024-09-23 20:14 不行 哪怕前端校验了 也要后端校验 万一前端被绕过了呢
from wtforms import StringField, Form, PasswordField, SelectField
from wtforms.validators import DataRequired, length, Email, Length, ValidationError, EqualTo

from app import logger
from app.models.User import User
from app.utils.Logger import WebLogger


class EmailForm(Form):
    email = StringField(validators=[DataRequired(), length(8, 64), Email(message="电子邮件不符合规范")])


class LoginForm(EmailForm):
    password = PasswordField(validators=[DataRequired(message="密码不可以为空"), Length(6, 32)])
    user_type = SelectField(
        choices=[('shop', '外卖平台用户'), ('bank', '银行用户')],
        validators=[DataRequired(message="请选择用户类型")]
    )


class RegisterForm(Form):
    nickname = StringField(validators=[
        DataRequired(),
        Length(3, 24, message='昵称长度必须在3到24个字符之间')
    ])
    email = StringField(validators=[
        DataRequired(),
        Email(message='无效的邮箱格式')
    ])
    password = PasswordField(validators=[
        DataRequired(),
        Length(6, 32)
    ])
    payPassword = StringField(validators=[
        DataRequired(),
        Length(6, 6, message='支付密码必须是六位数字')
    ])  # 支付密码字段
    user_type = SelectField(
        choices=[('shop', '外卖平台用户'), ('bank', '银行用户')],
        validators=[DataRequired(message="请选择用户类型")]
    )

    def validate_email(self, field):
        user_type = self.user_type.data
        if User.query.filter_by(email=field.data, user_type=user_type).first():
            raise ValidationError('该邮箱已被注册为该类型的用户')

    def validate_nickname(self, field):
        if User.query.filter_by(nickname=field.data).first():
            raise ValidationError('昵称已被占用')

    def validate_payPassword(self, field):
        if not re.match(r'^\d{6}$', field.data):
            raise ValidationError('支付密码必须是六位数字')


# class ResetPasswordForm(Form):
#     first_password = PasswordField(validators=[DataRequired(), Length(6, 32, message="密码长度至少需要6到32个字符之间"),
#                                                EqualTo("second_password", message="两次输入的密码不同")])
#     second_password = PasswordField(validators=[DataRequired(), Length(6, 32)])
#
#     def __init__(self,user, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.user = user
#
#     def validate_first_password(self, field):
#         if not self.user.verify_password(field.data):
#             raise ValidationError("新密码不能与原密码相同")
