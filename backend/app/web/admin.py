# encoding=utf-8
__author__ = 'Zephyr369'

from . import web

# TODO: 管理员审核 ,只有审核之后的账号才能进行办卡操作（模拟的是实名认证）同时开一个新的视图函数来让普通用户能够添加银行卡
@web.route("/examine" ,methods = ['POST', 'GET'])
def examine_the_user():
    pass