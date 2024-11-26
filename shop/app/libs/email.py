# encoding=utf-8
__author__ = 'Zephyr369'

from app import mail, logger

from app import mail
from flask_mail import Message
from flask import current_app, render_template
from threading import Thread


# 异步发送邮件
def send_async_mail(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            # 记录异常或处理错误
            logger.error(f"邮件发送失败: {e}")


def send_mail(to, subject, template, **kwargs):
    subj = f"{current_app.config['MAIL_SUBJECT_PREFIX']} {subject}"
    sender = current_app.config['MAIL_USERNAME']

    msg = Message(subject=subj, sender=sender, recipients=[to])
    msg.html = render_template(template, **kwargs)
    app = current_app._get_current_object()
    # current_app只是代理核心对象Flask，多线程隔离情况下，需要拿取真实的Flask对象
    # 使用 current_app 而不是 _get_current_object
    thr = Thread(target=send_async_mail, args=[app, msg])
    thr.start()
