from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import bcrypt
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager
)

app = Flask(__name__)
CORS(app) 

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['JWT_SECRET_KEY'] = 'your-super-secret-key-change-this' 
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) 
    name = db.Column(db.String(120), nullable=True)
    user_class = db.Column(db.String(50), nullable=True) 

    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Tên đăng nhập đã tồn tại!'}), 409

    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    new_user = User(
        username=data['username'],
        password=hashed_password.decode('utf-8'),
        name=data.get('name'),
        user_class=data.get('class')
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Đăng ký thành công!'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        access_token = create_access_token(identity=user.username)
        return jsonify(
            message='Đăng nhập thành công!', 
            access_token=access_token
        ), 200
    else:
        return jsonify({'message': 'Tên đăng nhập hoặc mật khẩu không đúng!'}), 401


@app.route('/data', methods=['GET'])
@jwt_required() 
def get_data():
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    if not user:
        return jsonify({'message': 'Không tìm thấy người dùng!'}), 404
    
    return jsonify({
        'username': user.username,
        'name': user.name,
        'class': user.user_class
    }), 200


@app.route('/admin/all_users', methods=['GET'])
@jwt_required() 
def get_all_users():
    all_users = User.query.all()
    users_list = []
    for user in all_users:
        users_list.append({
            'id': user.id,
            'username': user.username,
            'name': user.name,
            'class': user.user_class
        })
    return jsonify(all_users=users_list), 200

@jwt.unauthorized_loader
def unauthorized_callback(reason):
    return jsonify({
        "message": "Vui lòng đăng nhập để tiếp tục.",
        "reason": "missing_token"
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "message": "Phiên đăng nhập không hợp lệ hoặc đã hết hạn.",
        "reason": "invalid_token"
    }), 422 

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)