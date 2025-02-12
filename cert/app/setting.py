# encoding=utf-8
__author__ = 'Zephyr369'
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'aaaabbbbddddeeeeffff'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:<your_password>@127.0.0.1/certification'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
