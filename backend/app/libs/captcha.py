# encoding=utf-8
__author__ = 'Zephyr369'

# app/libs/captcha.py

import random
from datetime import datetime, timedelta
from flask import current_app
from app.libs.email import send_mail
from app.models.BankUser import BankUser
from app.models.ShopUser import ShopUser
from app import db, logger


# 对验证码进行管理 负责发邮件
class CaptchaManager:
    def __init__(self, user):
        self.victim = user
        self.expiration = current_app.config.get('CAPTCHA_EXPIRATION', 60)  # 默认60秒
        self.plain_captcha = None

    def generate_captcha(self):
        """生成验证码并保存明文和哈希版本"""
        # 生成明文验证码
        self.plain_captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])

        # 调用用户模型中的 generate_captcha 方法，保存哈希化验证码并设置过期时间
        self.victim.generate_captcha(self.plain_captcha, self.expiration)

    def send_captcha_email(self, subject, template):
        """发送明文验证码的邮件"""
        if not self.plain_captcha:
            raise ValueError("验证码未生成")

        # 发送邮件，使用明文验证码
        send_mail(self.victim.email, subject, template, user=self.victim, captcha=self.plain_captcha, expire = self.expiration)

    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        # 调用用户模型中的 verify_captcha 方法来验证输入的验证码
        return self.victim.verify_captcha(input_captcha)

