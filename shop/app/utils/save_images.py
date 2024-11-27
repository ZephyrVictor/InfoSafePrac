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
    保存上传的图片到指定目录，并按用户ID分类管理。

    参数:
    - image: 上传的文件对象 (通过 Flask 的 request.files 获取)
    - user_id: 当前用户的 ID，用于分类文件夹

    返回:
    - image_path: 保存的图片相对路径，用于数据库存储
    """
    # 检查文件类型是否允许
    if not allowed_file(image.filename):
        return jsonify({'error': 'Invalid file type. Only PNG, JPG, JPEG, GIF are allowed.'}), 400

    # 确保文件名安全
    filename = secure_filename(image.filename)

    # 确定上传目录
    upload_folder = os.path.join(current_app.root_path, 'upload', str(user_id))
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    # 文件存储路径
    file_path = os.path.join(upload_folder, filename)

    # 保存文件
    image.save(file_path)

    # 返回相对路径，用于存储在数据库中
    image_path = os.path.relpath(file_path, current_app.root_path)
    return image_path

    # 文件存储路径
    file_path = os.path.join(upload_folder, filename)

    # 保存文件
    image.save(file_path)

    # 返回相对路径，用于存储在数据库中
    image_path = os.path.relpath(file_path, current_app.root_path)
    return image_path
