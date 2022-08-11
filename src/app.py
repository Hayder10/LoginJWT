from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, create_refresh_token
from werkzeug.security import generate_password_hash, check_password_hash
from models import db,Admin, User, Product
from flask_cors import CORS

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['ENV'] = 'development'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['JWT_SECRET_KEY'] = '6c5c61586204fadea58b8be931023960'
app.config['JSON_SORT_KEYS'] = False

db.init_app(app)
Migrate(app,db)
CORS(app)
jwt = JWTManager(app)

#GET ALL ADMINS
@app.route('/api/admin', methods = ['GET','POST'])
def admin_list():
    if request.method == 'GET':
        admins = Admin.query.all()
        admins = list(map(lambda admin: admin.serialize(),admins))
        return jsonify(admins),200

    if request.method == 'POST':
        admin = Admin()
        admin.email = request.json.get('email')
        admin.password =  generate_password_hash(request.json.get('password'))
        admin.save()
        admin_list = Admin.query.all()
        return jsonify(list(map(lambda admin: admin.serialize(),admin_list))),200


#LOGIN ROUTE

@app.route('/api/login', methods = ['POST'])
def login():
    email = request.json.get('email')
    password =  request.json.get('password')
    #Comprobaciones datos ingresados
    if not email: return jsonify({"msg" : "Email is required."}),400
    if not password: return jsonify({"msg" : "Password is required."}),400

    admin_check = Admin.query.filter_by(email = email).first()
    if not admin_check:
        user = User.query.filter_by(email = email, is_active = True).first()

        if not user: return jsonify({"status" : "failed" , "msg" : "Username/Password are incorrect."}), 401
        if not check_password_hash(user.password,password): return jsonify({"status" : "failed" , "msg" : "Password is incorrect. Try again."}), 401

        access_token = create_access_token(identity=user.id)

        output = {
            "status" : "success",
            "msg" : "Successful Login",
            "is_admin" : False,
            "token" : access_token,
            "user" : user.serialize()
        }
        return jsonify(output),200

    else:
        if not check_password_hash(admin_check.password,password): return jsonify({"status" : "failed", "msg" : "Admin Password is incorrect. Try again."}),401
        access_token = create_access_token(identity=admin_check.id)
        output = {
            "status" : "success",
            "msg" : "Successful admin login",
            "is_admin" : True,
            "token" : access_token,
            "user" : admin_check.serialize()
        }
        return jsonify(output),200

    
    
    



#GET ALL USERS /// POST USER
@app.route('/api/users', methods = ['GET','POST'])
def get_and_post_users_with_products():

    #GET ALL USERS
    if request.method == 'GET':
        users = User.query.all()
        users = list(map(lambda user: user.serialize_with_products(), users))
        return jsonify(users),200
    
    #USER CREATION
    if request.method == 'POST':
        user = User()
        user.email = request.json.get('email')
        user.password = generate_password_hash(request.json.get('password'))
        user.empresa = request.json.get('empresa')
        user.phone = request.json.get('phone')
        user.firstName = request.json.get('firstName')
        user.lastName = request.json.get('lastName')
        user.run = request.json.get('run')

        user.save()
        
        all_users = User.query.all()
        all_users = list(map(lambda user: user.serialize(),all_users))
        return jsonify(all_users),200
    

#GET USER BY ID , EDIT USER, POST PRODUCT , DELETE USER
@app.route('/api/users/<int:id>', methods = ['GET','POST','PUT','DELETE'])
def get_edit_postProduct_user_by_id(id):
    #Get User by ID
    if request.method == 'GET':
        user = User.query.get(id)
        return jsonify(user.serialize_with_products()),200
    
    #Edit User
    if request.method == 'PUT':
        user = User.query.get(id)

        user.email = request.json.get('email')
        user.password = generate_password_hash(request.json.get('password'))
        user.empresa = request.json.get('empresa')
        user.phone = request.json.get('phone')
        user.firstName = request.json.get('firstName')
        user.lastName = request.json.get('lastName')
        user.run = request.json.get('run')
        user.is_active = request.json.get('is_active')
        
        user.update()
        users = User.query.all()
        return jsonify(list(map(lambda user: user.serialize(),users))),200

    if request.method == 'DELETE':
        user = User.query.get(id)
        user.delete()
        all_users = User.query.all()
        return jsonify(list(map(lambda user: user.serialize(),all_users))),200

    #Post Product
    if request.method == 'POST':
        product = Product()
        product.owner_id = id
        product.name = request.json.get('name')
        product.stock = request.json.get('stock')
        product.sold_stock = request.json.get('sold_stock')
        product.price = request.json.get('price')
        product.is_active = request.json.get('is_active')

        product.save()
        user = User.query.get(id)
        return jsonify(user.serialize_with_products()),200


#GET USER and PRODUCTS by ID
@app.route('/api/users/<int:id>/products', methods = ['GET'])
def get_products_by_user(id):
    if request.method == 'GET':
        user = User.query.get(id)
        return jsonify(user.serialize_with_products()),200
    
    
#GET PRODUCT by ID , AND EDIT PRODUCT by ID , DELETE PRODUCT by ID
@app.route('/api/users/<int:id>/products/<int:product_id>', methods = ['GET','PUT','DELETE'])
def get_product_by_id(id,product_id):
    if request.method == 'GET':
        product = Product.query.get(product_id)
        return jsonify(product.serialize()),200
    
    if request.method == 'PUT':
        product = Product.query.get(product_id)

        product.name = request.json.get('name')
        product.stock = request.json.get('stock')
        product.sold_stock = request.json.get('sold_stock')
        product.price = request.json.get('price')
        product.is_active = request.json.get('is_active')

        product.update()
        user = User.query.get(id)

        return jsonify(user.serialize_with_products()),200
    
    if request.method == 'DELETE':
        product = Product.query.get(product_id)
        product.delete()
        user = User.query.get(id)
        return jsonify(user.serialize_with_products()),200

#Edit Product by ID
@app.route('/api/users/products/<int:product_id>', methods = ['PUT'])
def edit_product_by_id(product_id):
    if request.method == 'PUT':
        product = Product.query.get(product_id)

        product.name = request.json.get('name')
        product.stock = request.json.get('stock')
        product.sold_stock = request.json.get('sold_stock')
        product.price = request.json.get('price')
        product.is_active = request.json.get('is_active')

        product.update()

        return jsonify(product.serialize()),200

if __name__ == '__main__':
    app.run()