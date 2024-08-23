from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config['SECRET_KEY'] = 'BlahBlahBlah'
app.config['JWT_SECRET_KEY'] = 'Something secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

class Order(db.Model):
    date = db.Column(db.String, primary_key=True, nullable=False,
                     info={'check_constraint': 'date GLOB "[0-3][0-9]-[0-1][0-9]-[0-9][0-9][0-9][0-9]"'})
    username = db.Column(db.String, nullable=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    total_price = db.Column(db.Float, nullable=False)

class User(db.Model):
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Product(db.Model):  # Fixed casing of Product class
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    item = db.Column(db.String, nullable=False)
    price = db.Column(db.Float, nullable=False)

    def as_dict(self):
        return {
            'id': self.id,
            'item': self.item,
            'price': self.price
        }

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_date = db.Column(db.String, db.ForeignKey('order.date'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

@app.route("/api/v1/sign_up", methods=['POST'])
def sign_up():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"response": "Username and password are required", "status": "failed"}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"response": "Username already exists", "status": "failed"}), 409
    
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"response": "Signup successful", "status": "success"}), 201

@app.route("/api/v1/login", methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Login Unsuccessful. Please check username and password"}), 401

@app.route("/api/v1/add_order", methods=['POST'])
@jwt_required()
def add_order():
    data = request.json
    item_id = data.get('item_id')
    quantity = data.get('quantity')

    if not item_id or not quantity:
        return jsonify({"error": "Item ID and quantity are required"}), 400

    product = Product.query.get(item_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    username = get_jwt_identity()
    order = Order(date=datetime.utcnow().strftime('%d-%m-%Y'), username=username)
    db.session.add(order)
    order_item = OrderItem(order_date=order.date, product_id=product.id, quantity=quantity, price=product.price * quantity)
    db.session.add(order_item)
    order.total_price += order_item.price
    db.session.commit()

    return jsonify({"message": "Order added successfully", "total_price": order.total_price}), 201

@app.route("/api/v1/get_all_orders", methods=['GET'])
@jwt_required()
def get_all_orders():
    username = get_jwt_identity()
    date = request.args.get('date')

    if date:
        try:
            datetime.strptime(date, '%d-%m-%Y')
        except ValueError:
            return jsonify({"error": "Invalid date format. Use DD-MM-YYYY"}), 400
        
        all_orders = Order.query.filter_by(username=username, date=date).all()
    else:
        all_orders = Order.query.filter_by(username=username).all()
    
    orders_list = [{
        'date': order.date,
        'total_price': order.total_price,
        'items': [{'item': item.product.item, 'quantity': item.quantity, 'price': item.price} for item in order.order_items]
    } for order in all_orders]
    
    return jsonify({"orders": orders_list}), 200

@app.route("/api/v1/admin", methods=['GET'])
@jwt_required()
def admin():
    products = Product.query.all()
    return jsonify([product.as_dict() for product in products]), 200

@app.route("/api/v1/make_order", methods=['GET'])
@jwt_required()
def make_order():
    return render_template('home.html')

@app.route("/api/v1/checkout", methods=['POST'])
@jwt_required()
def checkout():
    data = request.json
    items = data.get('items')

    username = get_jwt_identity()
    order = Order(date=datetime.utcnow().strftime('%d-%m-%Y'), username=username, total_price=0)
    db.session.add(order)

    for item in items:
        product = Product.query.get(item['product_id'])
        if product:
            order_item = OrderItem(order_date=order.date, product_id=product.id, quantity=item['quantity'], price=product.price * item['quantity'])
            db.session.add(order_item)
            order.total_price += order_item.price

    db.session.commit()

    return jsonify({"message": "Order placed successfully", "total_price": order.total_price}), 201

@app.route("/api/v1/logout", methods=['POST'])
@jwt_required()
def logout():
    return jsonify({"message": "Logout successful. Please delete your token client-side."}), 200

@app.route("/api/v1/users", methods=['GET'])
@jwt_required()
def user_list():
    users = User.query.order_by(User.username).all()
    users_list = [{'username': user.username} for user in users]
    return jsonify({"users": users_list}), 200

if __name__ == "__main__":
    app.run(debug=True)
