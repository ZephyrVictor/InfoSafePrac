# encoding=utf-8
__author__ = 'Zephyr369'

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.models.User import User
from app.models.Store import Store
from app import db
from . import web


# TODO: 管理员审核 ,只有审核之后的账号才能进行办卡操作（模拟的是实名认证）同时开一个新的视图函数来让普通用户能够添加银行卡
@web.route("/examine", methods=['POST', 'GET'])
@jwt_required()
def approve_user():
    '''
    管理员审核用户
    '''
    admin_id = get_jwt_identity()
    admin_user = User.query.get(admin_id)
    if not admin_user.isAdmin:
        return jsonify({'msg': '无权限'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': '用户不存在'}), 404

    user.isExamined = True
    db.session.commit()
    return jsonify({'msg': '用户审核通过'}), 200


@web.route("/approve_store", methods=['POST'])
@jwt_required()
def approve_store():
    """
    管理员审核店铺
    """
    admin_id = get_jwt_identity()
    admin_user = User.query.get(admin_id)
    if not admin_user.isAdmin:
        return jsonify({'msg': '无权限'}), 403

    data = request.get_json()
    store_id = data.get('store_id')

    store = Store.query.get(store_id)
    if not store:
        return jsonify({'msg': '店铺不存在'}), 404

    store.is_approved = True
    store.is_open = True
    db.session.commit()
    return jsonify({'msg': '店铺审核通过，已开业'}), 200


@web.route("/list_user", methods=['GET'])
@jwt_required()
def list_user():
    """
    列出所有用户
    """
    admin_id = get_jwt_identity()
    admin_user = User.query.get(admin_id)
    if not admin_user.isAdmin:
        return jsonify({'msg': '无权限'}), 403

    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'user_id': user.UserId,
            'email': user.email,
            'isExamined': user.isExamined,
            'isAdmin': user.isAdmin
        })

    return jsonify({'users': user_list}), 200





