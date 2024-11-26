# encoding=utf-8
__author__ = 'Zephyr369'

from flask_sqlalchemy import SQLAlchemy as _SQLAlchemy, BaseQuery
from sqlalchemy import Column, Integer, SmallInteger
from contextlib import contextmanager
from datetime import datetime


# 对sqlalchemy改写，commit失败了可以直接rollback 这样比较优雅，不需要在orm操作的时候有过多异常处理
class SQLAlchemy(_SQLAlchemy):
    @contextmanager
    def auto_commit(self):
        try:
            yield
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            # 正常抛出sqlalchemy的异常
            raise e


# 对filter_by做一个封装
class Query(BaseQuery):
    def filter_by(self, **kwargs):
        return super(Query, self).filter_by(**kwargs)


db = SQLAlchemy(query_class=Query)


class Base(db.Model):
    __abstract__ = True  # 不创建数据表
    create_time = Column('create_time', Integer)
    status = Column(SmallInteger, default=1)

    def __init__(self):
        self.create_time = int(datetime.now().timestamp())  # 时间戳

    def set_attrs(self, attrs_dict):
        for key, value in attrs_dict.items():
            if hasattr(self, key) and key != 'id':
                setattr(self, key, value)

    @property
    def create_datetime(self):
        if self.create_time:
            return datetime.fromtimestamp(self.create_time)
        else:
            return None

    def delete(self):
        self.status = 0
