from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# 初始化扩展
CORS(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
db = SQLAlchemy(app)

# 定义用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# 创建数据库
with app.app_context():
    db.create_all()

# 表单定义
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

# 防止XSS
def sanitize_input(input_string):
    return re.sub(r'[<>]', '', input_string)

# 注册接口
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    return jsonify({"errors": form.errors}), 400

# 登录接口
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=sanitize_input(form.email.data)).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            response = make_response(jsonify({"message": "Logged in successfully!"}), 200)
            response.set_cookie('session', session.sid, httponly=True)
            return response
        return jsonify({"message": "Invalid credentials"}), 401
    return jsonify({"errors": form.errors}), 400

# 简单留言板功能
messages = []

@app.route('/message', methods=['POST'])
@limiter.limit("10 per minute")
def post_message():
    if 'user_id' not in session:
        return jsonify({"message": "Unauthorized"}), 401

    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    content = sanitize_input(request.json.get('content'))
    messages.append({'username': user.username, 'content': content})
    return jsonify({"message": "Message posted successfully!"}), 201

@app.route('/messages', methods=['GET'])
def get_messages():
    return jsonify({"messages": messages}), 200

if __name__ == '__main__':
    app.run(debug=True)
