from flask import Flask, render_template, request, url_for, redirect, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, current_user, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from datetime import datetime
import uuid
import pdb


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config['SECRET_KEY'] = 'BlahBlahBlah'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()

class Order(db.Model):
    date = db.Column(db.String, primary_key=True, nullable=False, 
                     info={'check_constraint': 'date GLOB "[0-3][0-9]-[0-1][0-9]-[0-9][0-9][0-9][0-9]"'})
    username = db.Column(db.String, nullable=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    total_price = db.Column(db.Float, nullable=False)



class User(db.Model, UserMixin):
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()), nullable=False)
    username = db.Column(db.String, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    item = db.Column(db.String, nullable=False)
    price = db.Column(db.Float, nullable=False)


class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(str(user_id))


@app.route("/sign_up", methods=['GET', 'POST'])
def sign_up():
    if current_user.is_authenticated:
        return redirect(url_for('user_list'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            
            return jsonify({"redirect": url_for('sign_up')})


        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Sign up successful! Please log in.', 'success')
        return jsonify({"redirect": url_for('login')})
    return jsonify({"redirect": url_for('sign_up')})

@app.route("/login", methods=['POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({"redirect": url_for('make_order')})
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return jsonify({"redirect": url_for('make_order')}) if next_page else jsonify({"redirect": url_for('user_list')})
        
        else:
            return jsonify({"error": "Login Unsuccessful. Please check username and password"}), 401


    return jsonify({"error": "GET method not supported for login"}), 405

@app.route("/add_order")
def add_order():
    if request.method == 'POST':
        item = request.form.get('item')
        # password = request.form.get('password')

@app.route("/get_all_orders")
def get_all_orders():
    all_orders = Order.query.all()
    return all_orders

@app.route("/admin")
def admin():
    products = Product.query.all()
    return jsonify([product.as_dict() for product in products])

@app.route("/make_order")
def make_order():
    return render_template('home.html')

@app.route("/checkout")
def checkout():
    data = request.json
    user_id = data.get('user_id')
    items = data.get('items')  # This is a list of {'product_id': ..., 'quantity': ...}

    order = Order(user_id=user_id, total_price=0)
    db.session.add(order)
    db.session.commit()

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/users")
@login_required
def user_list():
    users = User.query.order_by(User.username).all()
    return render_template("user/list.html", users=users)


if __name__ == "__main__":
    app.run(debug=True)
