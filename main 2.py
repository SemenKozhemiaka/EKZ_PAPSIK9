from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Конфігурація
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Моделі бази даних
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="ROLE_USER")

# Ініціалізація бази даних
with app.app_context():
    db.create_all()
    # Додаємо адміністратора за замовчуванням, якщо його немає
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password=generate_password_hash("adminpass"),
            role="ROLE_ADMIN"
        )
        db.session.add(admin)
        db.session.commit()

# Маршрути
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"message": "Вкажіть ім'я користувача і пароль"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Користувач уже існує"}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Користувач зареєстрований успішно"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"message": "Вкажіть ім'я користувача і пароль"}), 400

    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Невірні облікові дані"}), 401

    token = create_access_token(identity={"username": user.username, "role": user.role})
    return jsonify({"token": token}), 200

@app.route('/user', methods=['GET'])
@jwt_required()
def user_route():
    current_user = get_jwt_identity()
    if current_user['role'] not in ["ROLE_USER", "ROLE_ADMIN"]:
        return jsonify({"message": "Доступ заборонено"}), 403

    return jsonify({"message": f"Вітаємо, {current_user['username']}! Ви маєте доступ до ресурсу користувача."}), 200

@app.route('/admin', methods=['GET'])
@jwt_required()
def admin_route():
    current_user = get_jwt_identity()
    if current_user['role'] != "ROLE_ADMIN":
        return jsonify({"message": "Доступ заборонено"}), 403

    return jsonify({"message": f"Вітаємо, адміністратор {current_user['username']}! Ви маєте доступ до адміністративного ресурсу."}), 200

if __name__ == '__main__':
    app.run(debug=True)
