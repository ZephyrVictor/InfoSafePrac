# encoding=utf-8
__author__ = 'Zephyr369'

# app/libs/captcha.py

import random
from datetime import datetime, timedelta
from flask import current_app
from app.libs.email import send_mail
from app.models.ShopUser import ShopUser
from app import db, logger


# 对验证码进行管理 负责发邮件
class CaptchaManager:
    def __init__(self, user=None, bank_card=None):
        """可以传递 BankCard 对象或 User 对象"""
        self.victim = user or bank_card
        self.bank_card = bank_card
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

        # 如果是 bank_card 对象，查找相关的用户来获取邮箱
        if self.bank_card:
            # 查找与 bank_card 关联的 BankUser（假设通过 user_id 查找）
            user = ShopUser.query.filter_by(UserId=self.bank_card.user_id).first()
            if not user or not user.email:
                raise ValueError("无法找到用户或用户的邮箱")
            email = user.email
        else:
            # 否则使用 user 对象的 email
            email = self.victim.email

        # 发送邮件，使用明文验证码
        send_mail(email, subject, template, user=self.victim, captcha=self.plain_captcha, expire=self.expiration)

    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        # 调用用户模型中的 verify_captcha 方法来验证输入的验证码
        return self.victim.verify_captcha(input_captcha)
