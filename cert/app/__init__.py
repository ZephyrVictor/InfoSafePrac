# encoding=utf-8
__author__ = 'Zephyr369'

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.setting import Config
from app.secure import SecureConfig

db = SQLAlchemy()
migrate = Migrate()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config.from_object(SecureConfig)

    db.init_app(app)
    migrate.init_app(app, db)

    from app.web import web_bp
    app.register_blueprint(web_bp)

    return app
