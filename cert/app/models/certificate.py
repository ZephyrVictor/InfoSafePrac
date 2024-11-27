# encoding=utf-8
__author__ = 'Zephyr369'

from app import db
from datetime import datetime


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    common_name = db.Column(db.String(120), unique=False, nullable=False)
    certificate_pem = db.Column(db.Text, nullable=False)
    private_key_pem = db.Column(db.Text, nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Certificate(common_name={self.common_name})>"
