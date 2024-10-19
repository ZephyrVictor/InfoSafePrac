# encoding=utf-8
__author__ = 'Zephyr369'

# app/libs/captcha.py

import random
from datetime import datetime, timedelta
from flask import current_app
from app.libs.email import send_mail
from app.models.BankUser import BankUser
from app.models.ShopUser import ShopUser
from app import db


class CaptchaManager:
    def __init__(self, user):
        self.user = user
        self.expiration = current_app.config.get('CAPTCHA_EXPIRATION', 60)

    def generate_captcha(self):
        """生成验证码并保存到用户模型中"""
        self.user.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.user.captcha_expiry = datetime.utcnow() + timedelta(seconds=self.expiration)
        db.session.commit()

    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        if self.user.captcha == input_captcha and datetime.utcnow() <= self.user.captcha_expiry:
            # 验证成功，清除验证码
            self.user.captcha = None
            self.user.captcha_expiry = None
            db.session.commit()
            return True
        return False

    def send_captcha_email(self, subject, template):
        """发送验证码邮件"""
        send_mail(self.user.email, subject, template, user=self.user, captcha=self.user.captcha)
