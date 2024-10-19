# encoding=utf-8
__author__ = 'Zephyr369'

from flasgger import swag_from
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.models.BankUser import BankUser
from app.models.ShopUser import ShopUser
# from app.models.User import User
from app.models.Store import Store
from app import db

admin_bp = Blueprint('admin', __name__)


# 管理员审核用户，只有审核过了的才能开卡
@admin_bp.route("/bank/examine", methods=['POST'])
@jwt_required()
def approve_user():
    """
    管理员审核用户
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            user_id:
              type: integer
              description: 待审核的用户ID
              example: 1
    responses:
      200:
        description: 用户审核通过
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 用户审核通过
      403:
        description: 无权限
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 无权限
      404:
        description: 用户不存在
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 用户不存在
    """
    admin_id = get_jwt_identity()
    admin_user = BankUser.query.get(admin_id)
    if not admin_user.isAdmin:
        return jsonify({'msg': '无权限'}), 403

    data = request.get_json()
    user_id = data.get('user_id')

    user = BankUser.query.get(user_id)
    if not user:
        return jsonify({'msg': '用户不存在'}), 404

    user.isExamined = True
    db.session.commit()
    return jsonify({'msg': '用户审核通过'}), 200


@admin_bp.route("/bank/list_user", methods=['GET'])
# @swag_from('../docs/bank_list_user.yml')
@jwt_required()
def bank_list_user():
    """
    tags:
      - Admin
    security:
      - Bearer: []  # 这里定义了需要 Bearer Token 的安全验证
    responses:
      200:
        description: 成功返回银行用户列表
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
                properties:
                  user_id:
                    type: integer
                    example: 1
                  email:
                    type: string
                    example: user@example.com
                  isExamined:
                    type: boolean
                    example: true
                  isAdmin:
                    type: boolean
                    example: false
      403:
        description: 无权限
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 无权限
        :return:
    """
    admin_id = get_jwt_identity()
    admin_user = BankUser.query.get(admin_id)
    if not admin_user.isAdmin:
        return jsonify({'msg': '无权限'}), 403

    users = BankUser.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'user_id': user.UserId,
            'email': user.email,
            'isExamined': user.isExamined,
            'isAdmin': user.isAdmin
        })

    return jsonify({'users': user_list}), 200


@admin_bp.route("/shop/list_user", methods=['GET'])
@jwt_required()
def shop_list_user():
    """
    列出所有用户
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    responses:
      200:
        description: 成功返回外卖商户用户列表
        schema:
          type: object
          properties:
            users:
              type: array
              items:
                type: object
                properties:
                  user_id:
                    type: integer
                    example: 1
                  email:
                    type: string
                    example: user@example.com
                  isExamined:
                    type: boolean
                    example: true
                  isAdmin:
                    type: boolean
                    example: false
      403:
        description: 无权限
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 无权限
    """
    admin_id = get_jwt_identity()
    admin_user = ShopUser.query.get(admin_id)
    if not admin_user:
        return jsonify({"msg":"没有管理员用户"}), 403
    if not admin_user.isAdmin:
        return jsonify({'msg': '无权限'}), 403

    users = ShopUser.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'user_id': user.UserId,
            'email': user.email,
            'Stores': user.stores,
            'isAdmin': user.isAdmin
        })

    return jsonify({'users': user_list}), 200


@admin_bp.route("/shop/approve_store", methods=['POST'])
@jwt_required()
def approve_store():
    """
    管理员审核店铺
    ---
    tags:
      - Admin
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            store_id:
              type: integer
              description: 待审核的店铺ID
              example: 1
    responses:
      200:
        description: 店铺审核通过，已开业
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 店铺审核通过，已开业
      403:
        description: 无权限
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 无权限
      404:
        description: 店铺不存在
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 店铺不存在
    """
    admin_id = get_jwt_identity()
    admin_user = ShopUser.query.get(admin_id)
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
