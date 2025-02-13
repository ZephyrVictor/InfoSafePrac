# 环境

## 商城与银行
`bank`(backend)、`shop`使用`Python 3.10.15`

使用`conda create python=3.10.15 0 --name <your_name>`来创建一个环境
然后`pip install -r requirements.txt`来安装依赖

## CA机构

`conda create python=3.10.13 --name <your_name>`

安装依赖方法同上

# 配置

## 服务器配置

在`app/secure.py`下配置好对应的数据库连接，名称，密码
配置好smtp_token

## 数据库迁移


`flask db migrate`
`flask db upgrade`

## 项目启动

我是懒狗，如果`node_modules`存在，就可以直接运行，否则，要在`./app`目录下 `npm install`一下

要先启动`cert`，再启动`bank`，然后再启动`shop`。 


---

项目用不到三天一个人搓出来的，时间紧任务重屎山大，自己都没眼看第二遍，参考参考。能跑起来且有用就已经是最大的收获了。