# encoding=utf-8
__author__ = 'Zephyr369'

from . import web

#
@web.route("/examine" ,methods = ['POST', 'GET'])
def