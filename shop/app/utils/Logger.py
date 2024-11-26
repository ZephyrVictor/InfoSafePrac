# encoding=utf-8
__author__ = 'Zephyr369'

import logging


# 日志管理器 分为基本的级别 只有在WARNING级别以上的才会被记录
class WebLogger:
    def __init__(self, name='WebLogger', log_file='app.log'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        # 创建文件处理器
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.WARNING)

        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)

        # 创建日志格式
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # 添加处理器到日志器
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def debug(self, message):
        self.logger.debug(message)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def critical(self, message):
        self.logger.critical(message)
