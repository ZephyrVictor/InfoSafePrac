-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA8Pp8ZqedIyVF6D9dIHKOdTtq6OZCog3ZlQ/RGFUlHwWUK6og
Y2bepVZgpC8onYRLP6LqYCqOYIMn+KcZPO8RXhoDPMVkITElOnpz+VUA3mV93gDK
sae0mZW2BMI4Rm9M8zYKFhTrCQE1dHbBG5zj2k4Vz8ofJPqQrSnrNLEckYcgJdUc
HPSNEoij3ZTGlsO21qDX27KSuox2mam7p1maKdJuay76bNxPv+7gOOAHy3rBDwrg
xMUyxtl/5/HtLe8bU8wxXo3D0wPTrkL5vZElsed8MjtG7qMFj5XKhITyo0IcIBYj
T15nLaLqmKtFfzQdUxFH8NKiOkuEcdtOtesShwIDAQABAoIBADOhX2z5JZRFpKQ9
izzr/nTErcPHregdsowa7vBZMdJjNhti4HybqkFfb+ZNilSxZxPz2maPR6ELCNHg
L2qcSCrSxPXMzwbDilfsq5N0sHJ16VFa9xK4PVwYtP5xBHCm4SRM5D1V7wOnZCYX
WYmKhFEeINM72Y9pNf07+X55IgdVs1BtpH+B4xv6zyM3VylgONFCuPTWN5GYUi96
8ViaxGsTKWv9JnWGWe8P4e6+V1teE/9UL5jCbA5Lmik+Cnuzf8Jre3cMBbs1gBtq
kztAv2QFQtv7moaAj3VUjY+OkTefxXqRf8NaMiYjob1RVo7Af2pwgCQPQCtJzJXV
kPkmQd0CgYEA+o96YdtEAclhBTliPak2KQ1U5zVoLScqUFFUYpPOTz42Itpe7LgT
uXiWE3NrzojawadLkc4HVlQWc81GG58paQFf4wSQUb2BgKfzIVhtjh+dnaGP4ThO
4EvkP33wI7Fby1CFcSz9HiijVu0tqnnce3W9JE8+LWtXwafEp+9CZZsCgYEA9jXB
MzPomGDnKylaUZBDe/Jq3blZQd9WqudBq4c41JTaicT2jPgbgWMES9NVGbKKkZ2n
rnsFbH4lCxYHC7ZagRIR6mCsEpdnz0i8VIT4zxBSQhZc7+pcPbu7CzOTIEXdp1wF
vLPHQUPUJGAlmCzSbbt0rBEYjLfxxE8vn41l64UCgYBXI17keWUFWgurzXElEJwN
Wt2UKza3vU8x75bxUYYGeRRKurcYjEwPzKgky5dKlL2/a3cUlhpnI4dLbrBbGtdD
9X5rbULjqoxHOiGMDzzKmKQwFef746FK0BnpGttRDnVmF/LQkVzWCDwGFyYyi37q
UOAeqJBvK02xw67Y2JS20QKBgFFVvLc/hK0iBfv6Mz4SnFiL4sXQfy4Fq8nVj5os
l5eSfQdaK+Cx7dQ2c6rg65ILqz8jh8taFJacrXwWEMnLueY9o/F7chzKK58Mdjqt
msw8pg/y90zCbSpvpAC1TvswWWL6QWLvOPnUgHZr1L+KvxFFBev50dRax+GED0V0
HqFJAoGAaHVoyWf1WHRrx7pP/sB53LtrqaquDQXZoic5VP2lyOOc1egJAVjlTT96
Hdvu7oGksnKULkfIXg7PGTOmqNgqXtAQkEpj9fRcdzBKclhDKbrzf/iGKZ1O6vaL
M2YQ2w4M6xd+ZnkfiPNr0HbsqTZpCJSF1kGqbbb8KyN041J4X/s=
-----END RSA PRIVATE KEY-----
帮我用tailwindcss写一个flask下的前端template
布局大概如图所示
这个是商城的主界面
上面一个大header 图片为 url for static/shopbg.jpg 参考国外常用的页面布局
然后下面分一行三个栏目 上半部分是一个商品的图片 如果没有图片 默认选取 static/default.jpg
然后下面是一个加粗的商品名称 右侧是蓝色的价格 ￥xxx 下面是字体稍微小的描述
这是一个简单的组件事例
div class="flex font-sans">
  <div class="flex-none w-48 relative">
    <img src="/classic-utility-jacket.jpg" alt="" class="absolute inset-0 w-full h-full object-cover" loading="lazy" />
  </div>
  <form class="flex-auto p-6">
    <div class="flex flex-wrap">
      <h1 class="flex-auto text-lg font-semibold text-slate-900">
        Classic Utility Jacket
      </h1>
      <div class="text-lg font-semibold text-slate-500">
        $110.00
      </div>
      <div class="w-full flex-none text-sm font-medium text-slate-700 mt-2">
        In stock
      </div>
    </div>
    <div class="flex items-baseline mt-4 mb-6 pb-6 border-b border-slate-200">
      <div class="space-x-2 flex text-sm">
        <label>
          <input class="sr-only peer" name="size" type="radio" value="xs" checked />
          <div class="w-9 h-9 rounded-lg flex items-center justify-center text-slate-700 peer-checked:font-semibold peer-checked:bg-slate-900 peer-checked:text-white">
            XS
          </div>
        </label>
        <label>
          <input class="sr-only peer" name="size" type="radio" value="s" />
          <div class="w-9 h-9 rounded-lg flex items-center justify-center text-slate-700 peer-checked:font-semibold peer-checked:bg-slate-900 peer-checked:text-white">
            S
          </div>
        </label>
        <label>
          <input class="sr-only peer" name="size" type="radio" value="m" />
          <div class="w-9 h-9 rounded-lg flex items-center justify-center text-slate-700 peer-checked:font-semibold peer-checked:bg-slate-900 peer-checked:text-white">
            M
          </div>
        </label>
        <label>
          <input class="sr-only peer" name="size" type="radio" value="l" />
          <div class="w-9 h-9 rounded-lg flex items-center justify-center text-slate-700 peer-checked:font-semibold peer-checked:bg-slate-900 peer-checked:text-white">
            L
          </div>
        </label>
        <label>
          <input class="sr-only peer" name="size" type="radio" value="xl" />
          <div class="w-9 h-9 rounded-lg flex items-center justify-center text-slate-700 peer-checked:font-semibold peer-checked:bg-slate-900 peer-checked:text-white">
            XL
          </div>
        </label>
      </div>
    </div>
    <div class="flex space-x-4 mb-6 text-sm font-medium">
      <div class="flex-auto flex space-x-4">
        <button class="h-10 px-6 font-semibold rounded-md bg-black text-white" type="submit">
          Buy now
        </button>
        <button class="h-10 px-6 font-semibold rounded-md border border-slate-200 text-slate-900" type="button">
          Add to bag
        </button>
      </div>
      <button class="flex-none flex items-center justify-center w-9 h-9 rounded-md text-slate-300 border border-slate-200" type="button" aria-label="Like">
        <svg width="20" height="20" fill="currentColor" aria-hidden="true">
          <path fill-rule="evenodd" clip-rule="evenodd" d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z" />
        </svg>
      </button>
    </div>
    <p class="text-sm text-slate-700">
      Free shipping on all continental US orders.
    </p>
  </form>
</div>


这个到时候会根据商品的model来定
商品model大概需要名称 所属的用户 用户可以自建多个种类 （对应上面的尺码） 图片 
以及购买数量等
这是我现有的model
# app/models/item.py

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.models.ShopUser import ShopUser


class item(Base):
    __tablename__ = 'item'

    ItemId = Column(Integer, primary_key=True)
    Item_name = Column(String(50), nullable=False)
    Item_type = Column(String(50), nullable=False)
    # owner_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    is_approved = Column(Boolean, default=False)
    is_open = Column(Boolean, default=False)
    description = Column(String(256), nullable=False)
    image_path = Column(String(256), nullable=False)

    owner_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    owner = relationship('ShopUser', back_populates='stores')
    orders = relationship('Order', backref='store', lazy='dynamic')

# app/models/ShopUser.py

# encoding=utf-8
__author__ = 'Zephyr369'

import random
from datetime import datetime, timedelta

import jwt
from flask import current_app
from flask_jwt_extended import create_access_token, decode_token
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from werkzeug.security import generate_password_hash, check_password_hash

from app import login_manager, logger
from app.models.base import Base, db


# TODO: 将ShopUser继承于AbstractUser
class ShopUser(UserMixin, Base):
    __tablename__ = 'shop_user'

    UserId = Column(Integer, primary_key=True)  # 用户ID
    nickname = Column(String(24), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    _password = Column('password', String(255), nullable=False)
    isAdmin = Column(Boolean, default=False)  # 是否为管理员
    _captcha = Column("captcha", String(255), nullable=True)  # 验证码
    bank_user_id = Column(Integer, nullable=True)  # 关联的银行用户ID
    captcha_expiry = Column(DateTime, nullable=True)  # 验证码过期时间
    stores = db.relationship('Store', back_populates='owner', lazy='dynamic')

    # 验证码还是用哈希来保存好了
    @property
    def captcha(self):
        return self._captcha

    @captcha.setter
    def captcha(self, raw):
        # 避免生成哈希时传递None
        if raw:
            self._captcha = generate_password_hash(raw)
        else:
            self._captcha = None

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, raw):
        self._password = generate_password_hash(raw)

    def verify_password(self, raw):
        return check_password_hash(self._password, raw)

    def set_captcha(self):
        """生成验证码"""
        self.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        db.session.commit()

    # 返回验证码是否正确
    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        # 避免None值传递给check_password_hash
        if self._captcha and check_password_hash(self._captcha, input_captcha):
            if datetime.utcnow() <= self.captcha_expiry:
                # 验证成功，清除验证码
                self.captcha = None
                self.captcha_expiry = None
                db.session.commit()
                return True
        return False

    def generate_captcha(self, captcha_value, expiry_seconds=60):
        """生成哈希化验证码并设置过期时间"""
        self.captcha = captcha_value  # 触发setter进行哈希化
        self.captcha_expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)
        db.session.commit()

    @staticmethod
    def reset_password(user_id, new_password):
        try:
            user = ShopUser.query.get(user_id)
            user.password = new_password
            db.session.commit()
            return True
        except Exception as e:
            logger.error(f"重置密码失败: {e}")
            return False

    @staticmethod
    def generate_jwt(user, remember=False):
        expires = timedelta(days=7) if remember else timedelta(days=1)
        return create_access_token(
            identity=user.UserId,
            expires_delta=expires,
            additional_claims={'user_type': 'shop'}  # 在jwt中存一个用户类型
        )

    def generate_token(self, expiration=600):
        secret_key = current_app.config['SECRET_KEY']
        payload = {
            'UserId': self.UserId,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration)
        }
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        return token

    @staticmethod
    def get_user_from_jwt(token):
        try:
            decoded_token = decode_token(token)
            user_id = decoded_token['identity']
            return ShopUser.query.get(user_id)
        except Exception as e:
            logger.error(f'JWT解析失败: {e}')
            return None


@login_manager.user_loader
def load_user(user_id):
    return ShopUser.query.get(int(user_id))
# app/models/Order.py

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from app.models.base import Base
from app.models.ShopUser import ShopUser


class Order(Base):
    __tablename__ = 'order'

    OrderId = Column(Integer, primary_key=True)
    order_number = Column(String(50), unique=True, nullable=False)
    buyer_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    seller_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    store_id = Column(Integer, ForeignKey('store.StoreId'), nullable=False)
    amount = Column(Float, nullable=False)
    order_time = Column(DateTime, default=datetime.utcnow)
    details = Column(String(255), nullable=False)

    buyer = relationship('ShopUser', foreign_keys=[buyer_id], backref='purchases')
    seller = relationship('ShopUser', foreign_keys=[seller_id], backref='sales')


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

然后 我复用了之前bankuser下的注册和登录
你可以修改他们的代码

@auth_bp.route("/bank/register", methods=['GET', 'POST'])
def bank_register():
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        password = request.form.get('password')
        payPassword = request.form.get('payPassword')

        if not all([nickname, email, password, payPassword]):
            flash('所有字段都是必需的', 'error')
            return redirect(url_for('web.auth.bank_register'))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_register'))

        existing_user = BankUser.query.filter_by(email=email).first()
        if existing_user:
            flash('该邮箱已被注册', 'error')
            return redirect(url_for('web.auth.bank_register'))

        user = BankUser(
            nickname=nickname,
            email=email,
            password=password,
            payPassword=payPassword
        )
        db.session.add(user)
        db.session.commit()

        flash('银行用户注册成功，请登录', 'success')
        return redirect(url_for('web.auth.bank_login'))
    return render_template('auth/bank_register.html')


@auth_bp.route('/bank/login', methods=['GET', 'POST'])
def bank_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        if not email or not password:
            flash('邮箱和密码是必需的', 'error')
            return redirect(url_for('web.auth.bank_login'))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_login'))

        user = BankUser.query.filter_by(email=email).first()
        if user is None:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.bank_login'))

        if not user.verify_password(password):
            logger.info(f"银行用户 {user.nickname} 密码输入错误")
            flash('密码不正确', 'error')
            return redirect(url_for('web.auth.bank_login'))

        access_token = user.generate_jwt(user, remember)
        logger.info(f"银行用户 {user.nickname} 登录成功")
        response = make_response(redirect(url_for('web.bank.dashboard')))
        response.set_cookie(
            'access_token',
            access_token,
            httponly=True,
            secure=False,  # 如果使用 HTTPS，请设为 True
            samesite='Lax',
            max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
        )
        csrf_token = create_access_token(identity=user.UserId)  # 生成 CSRF token
        response.set_cookie(
            'csrftoken',
            csrf_token,
            httponly=False,  # CSRF token 需要允许前端读取
            secure=True,  # 如果使用 HTTPS，请设为 True
            samesite='Lax',
            max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
        )
        flash('登录成功', 'success')
        return response
    return render_template('auth/bank_login.html')


@auth_bp.route("/bank/activate", methods=['GET', 'POST'])
@jwt_required()
def bank_activate():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    if user.isExamined:
        flash('您的账户已激活，无需再次激活。', 'info')
        return redirect(url_for('web.bank.dashboard'))

    if request.method == 'POST':
        # 处理表单提交，在 confirm_activate 函数中处理
        return redirect(url_for('web.auth.confirm_activate'))

    # 发送激活邮件
    captcha_manager = CaptchaManager(user)
    captcha_manager.generate_captcha()
    captcha_manager.send_captcha_email("激活您的账户验证码", 'email/activate_account.html')
    flash('激活验证码已发送，请查收您的邮箱。', 'info')
    return render_template('auth/activate_account.html')


@auth_bp.route("/bank/activate/confirm", methods=['POST'])
@jwt_required()
def confirm_activate():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    if user.isExamined:
        flash('您的账户已激活，无需再次激活。', 'info')
        return redirect(url_for('web.bank.dashboard'))

    captcha = request.form.get('captcha')

    if not captcha:
        flash('请输入验证码。', 'error')
        return redirect(url_for('web.auth.bank_activate'))

    captcha_manager = CaptchaManager(user)
    if captcha_manager.verify_captcha(captcha):
        user.isExamined = True
        db.session.commit()
        flash('账户激活成功！', 'success')
        return redirect(url_for('web.bank.dashboard'))
    else:
        flash('验证码错误或已过期，请重新获取。', 'error')
        return redirect(url_for('web.auth.bank_activate'))


@auth_bp.route("/bank/reset/password", methods=['GET', 'POST'])
def bank_reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash('请输入有效的邮箱地址', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))

        user = BankUser.query.filter_by(email=email).first()
        if user:
            captcha_manager = CaptchaManager(user)
            captcha_manager.generate_captcha()
            captcha_manager.send_captcha_email("重置您的密码验证码", 'email/reset_password.html')
            flash('重置密码验证码已发送，请查收', 'info')
            return redirect(url_for('web.auth.bank_reset_password', email=email))
        else:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))
    return render_template('auth/bank_reset_password_request.html')


@auth_bp.route("/bank/reset/password/confirm", methods=['GET', 'POST'])
def bank_reset_password():
    email = request.args.get('email')
    if request.method == 'POST':
        email = request.form.get('email')
        captcha = request.form.get('captcha')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not all([email, captcha, new_password, confirm_password]):
            flash('所有字段都是必需的', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))

        # 验证邮箱格式是否有效
        if not is_valid_email(email):
            flash('无效的邮箱格式', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))

        if new_password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))

        user = BankUser.query.filter_by(email=email).first()
        if not user:
            flash('用户不存在', 'error')
            return redirect(url_for('web.auth.bank_reset_password_request'))

        captcha_manager = CaptchaManager(user)
        if captcha_manager.verify_captcha(captcha):
            if user.verify_password(new_password):
                flash('新密码不能与原密码相同', 'error')
                return redirect(url_for('web.auth.bank_reset_password', email=email))
            user.password = new_password
            db.session.commit()
            flash('密码重置成功，请登录', 'success')
            return redirect(url_for('web.auth.bank_login'))
        else:
            flash('验证码错误或已过期', 'error')
            return redirect(url_for('web.auth.bank_reset_password', email=email))
    return render_template('auth/bank_reset_password.html', email=email)


@auth_bp.route('/bank/logout')
@login_required
def logout():
    logout_user()
    flash('您已成功退出登录', 'info')
    return redirect(url_for('web.auth.bank_login'))


同时请你完成下面的需求 给出前端和后端代码
1 用户可以登录和注册 注册需要通过输入邮箱验证码来激活这个账号
2 首先会进入到商城主界面，主界面可以浏览商品，并可以保持未登录状态，但浏览商品和其他操作都需要先跳转到登录界面 登录结束后再进一步操作
3 用户可以绑定自己的银行账号 为此你需要给银行的平台实现一个oauth来进行认证授权 同时应该记录到对应的数据表中   你需要给出bank模块下的oauth的实现方法 这是对应的model
# app/models/BankUser.py

# encoding=utf-8
__author__ = 'Zephyr369'

# import datetime
import random
from datetime import datetime, timedelta
from flask_login import UserMixin
import jwt
from flask import current_app
from flask_jwt_extended import create_access_token, decode_token
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from werkzeug.security import generate_password_hash, check_password_hash

from app import logger
from app.models.base import Base, db

# TODO: 将BankUser继承于AbstractUser
class BankUser(Base):
    __tablename__ = 'bank_user'

    UserId = Column(Integer, primary_key=True)  # 用户ID
    nickname = Column(String(24), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    _password = Column('password', String(255), nullable=False)
    isExamined = Column(Boolean, default=False)  # 是否经过审核
    _payPassword = Column('pay_password', String(255), nullable=False)  # 支付密码
    isAdmin = Column(Boolean, default=False)  # 是否为管理员
    IdCardNumber = Column(String(18), nullable=True)  # 身份证号
    _captcha = Column("captcha",String(255), nullable=True)  # 验证码
    captcha_expiry = Column(DateTime, nullable=True) # 验证码过期时间
    bank_cards = db.relationship('BankCard', back_populates='user', lazy='dynamic')

    @property
    def captcha(self):
        return self._captcha

    @captcha.setter
    def captcha(self, raw):
        if raw:
            self._captcha = generate_password_hash(raw)
        else:
            self._captcha = None

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, raw):
        self._password = generate_password_hash(raw)

    @property
    def payPassword(self):
        return self._payPassword

    @payPassword.setter
    def payPassword(self, raw):
        self._payPassword = generate_password_hash(raw)

    def verify_payPassword(self, raw):
        return check_password_hash(self._payPassword, raw)

    def verify_password(self, raw):
        return check_password_hash(self._password, raw)

    def set_captcha(self):
        """生成验证码"""
        self.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        db.session.commit()

    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        if self._captcha and check_password_hash(self._captcha, input_captcha):
            if datetime.utcnow() <= self.captcha_expiry:
                self.captcha = None
                self.captcha_expiry = None
                db.session.commit()
                return True
        return False

    def generate_captcha(self, captcha_value, expiry_seconds=60):
        """生成哈希化验证码并设置过期时间"""
        self.captcha = captcha_value  # 触发setter进行哈希化
        self.captcha_expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)
        db.session.commit()

    @staticmethod
    def reset_password(user_id, new_password):
        try:
            user = BankUser.query.get(user_id)
            user.password = new_password
            db.session.commit()
            return True
        except Exception as e:
            logger.error(f"重置密码失败: {e}")
            return False

    @staticmethod
    def generate_jwt(user, remember=False):
        expires = timedelta(days=7) if remember else timedelta(days=1)
        print(f"Generating JWT for user_id: {user.UserId}")  # 打印user_id
        return create_access_token(
            identity=user.UserId,
            expires_delta=expires,
            additional_claims={'user_type': 'bank'} # 银行用户
        )

    def generate_token(self, expiration=600):
        secret_key = current_app.config['SECRET_KEY']
        payload = {
            'UserId': self.UserId,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration)
        }
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        return token

    @staticmethod
    def get_user_from_jwt(token):
        try:
            decoded_token = decode_token(token)
            user_id = decoded_token['identity']
            return BankUser.query.get(user_id)
        except Exception as e:
            logger.error(f'JWT解析失败: {e}')
            return None

    def get_id(self):
        return str(self.UserId)

    def get_name(self):
        return self.nickname
class BankCard(Base):
    __tablename__ = 'bank_card'

    CardId = Column(Integer, primary_key=True)
    card_number = Column(String(19), unique=True, nullable=False)
    # user_id = Column(Integer, ForeignKey('bank_user.UserId'), nullable=False)
    balance = Column(Float, default=0.0)
    is_active = Column(Boolean, default=False)
    _captcha = Column("captcha",String(255), nullable=True)  # 验证码

# TODO: 为 BankCard 添加一个 captcha_expiry 字段，用于保存验证码的过期时间
    user_id = Column(Integer, ForeignKey('bank_user.UserId'), nullable=False)
    user = relationship('BankUser', back_populates='bank_cards')

    def __init__(self, user_id, **kwargs):
        super(BankCard, self).__init__(**kwargs)
        self.user_id = user_id  # 设置 user_id
        if not self.card_number:
            self.card_number = self.generate_card_number()
4 用户可以上传需要售卖的商品，提交的表单包括但不限于 商品名称 价格 若干个种类 商品图片
5 应当有订单管理机制和购物车机制 用户在商城通过购买商品或者在购物车中选择商品（一件、多件或全部） 进行结算 
6 你需要实现银行系统和商店系统之间订单的交互 并保证安全性  用户发起在商品界面或购物车界面进行结算，发起一个支付，然后跳转到对应的银行的结算界面，用户输入支付密码后进行结算，若余额不足，则支付失败，返回到 订单界面，订单有效期为15分钟，可以选择没有结算的订单进行支付 。当用户支付成功后，返回到订单界面，显示订单支付成功，用户完成购买，此时对应卖家的银行账户应该增加对应的金额。而买家对应的银行账户应该减少一部分金额  因此我们需要一套完整的管理机制

