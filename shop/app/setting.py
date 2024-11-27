# encoding=utf-8
__author__ = 'Zephyr369'
DEBUG = True
# TODO : 衔接好bank侧接口
class Config:
    # ... existing config ...
    BANK_OAUTH_CLIENT_ID = 'your_client_id'
    BANK_OAUTH_CLIENT_SECRET = 'your_client_secret'
    BANK_OAUTH_AUTHORIZE_URL = 'https://bank.example.com/oauth/authorize'
    BANK_OAUTH_TOKEN_URL = 'https://bank.example.com/oauth/token'
    BANK_OAUTH_USERINFO_URL = 'https://bank.example.com/api/userinfo'