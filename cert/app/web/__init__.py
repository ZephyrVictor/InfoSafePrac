# encoding=utf-8
__author__ = 'Zephyr369'
from flask import Blueprint

web_bp = Blueprint('web', __name__)

from app.web import views
