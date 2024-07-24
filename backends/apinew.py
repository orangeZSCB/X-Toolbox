from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 文件路径
USER_FILE = 'users.json'
MESSAGE_FILE = 'messages.json'

# 初始化文件
def init_files():
    if not os.path.exists(USER_FILE):
        with open(USER_FILE, 'w') as f:
            json.dump([], f)
    if not os.path.exists(MESSAGE_FILE):
        with open(MESSAGE_FILE, 'w') as f:
            json.dump([], f)

init_files()

# 注册接口
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': '用户名和密码不能为空'}), 400
    
    with open(USER_FILE, 'r') as f:
        users = json.load(f)
    
    if any(user['username'] == username for user in users):
        return jsonify({'message': '用户名已存在'}), 400
    
    users.append({'username': username, 'password': password})
    
    with open(USER_FILE, 'w') as f:
        json.dump(users, f)
    
    return jsonify({'message': '注册成功'}), 201

# 登录接口
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    with open(USER_FILE, 'r') as f:
        users = json.load(f)
    
    if any(user['username'] == username and user['password'] == password for user in users):
        return jsonify({'message': '登录成功'}), 200
    else:
        return jsonify({'message': '用户名或密码错误'}), 400

# 留言接口
@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if request.method == 'GET':
        with open(MESSAGE_FILE, 'r') as f:
            messages = json.load(f)
        return jsonify(messages), 200
    
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        content = data.get('content')
        
        if not username or not content:
            return jsonify({'message': '用户名和内容不能为空'}), 400
        
        # 防止 XSS 攻击
        content = content.replace('<', '&lt;').replace('>', '&gt;')
        
        with open(MESSAGE_FILE, 'r') as f:
            messages = json.load(f)
        
        messages.append({'username': username, 'content': content})
        
        with open(MESSAGE_FILE, 'w') as f:
            json.dump(messages, f)
        
        return jsonify({'message': '留言成功'}), 201

if __name__ == '__main__':
    app.run(debug=True)
