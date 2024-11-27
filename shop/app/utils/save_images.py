# encoding=utf-8
__author__ = 'Zephyr369'

import os

from flask import current_app, jsonify
from werkzeug.utils import secure_filename

# 允许的文件类型
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    """
    检查文件类型是否在允许的范围内。
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_image(image, user_id):
    """
    保存上传的图片到指定目录，并返回存储路径。

    参数:
    - image: 上传的文件对象
    - user_id: 当前用户的 ID

    返回:
    - image_path: 图片的相对路径，供存储到数据库
    """
    # 确定上传目录
    upload_folder = os.path.join('./app/static', 'upload', str(user_id))
    os.makedirs(upload_folder, exist_ok=True)

    # 确保文件名安全
    filename = secure_filename(image.filename)
    file_path = os.path.join(upload_folder, filename)

    # 保存文件
    image.save(file_path)

    result_path = os.path.join("/upload",str(user_id),filename)

    # 将路径格式化为正斜杠并返回 而且这个妈了个逼的为了前端渲染endpoint是static 会出现/static/static的情况 应该去掉
    return result_path.replace("\\", "/")
