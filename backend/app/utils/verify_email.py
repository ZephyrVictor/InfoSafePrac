# encoding=utf-8
__author__ = 'Zephyr369'

import re


def is_valid_email(email):
    """
    验证邮箱是否符合格式
    :param email: 待验证的邮箱字符串
    :return: 如果符合格式返回 True，否则返回 False
    """
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if re.match(email_regex, email):
        return True
    return False