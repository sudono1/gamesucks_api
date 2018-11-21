from flask import Flask
from flask_restful import Resource, Api, reqparse, marshal, fields
from flask_cors import CORS

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, insert, ForeignKey, DateTime, distinct, func
from sqlalchemy.orm import relationship
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_claims, jwt_required, get_jwt_identity, get_raw_jwt
from functools import wraps
import sys, json, datetime, math
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

app = Flask(__name__)
CORS(app, resources={r"*": {"origin": "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://sudono:alphatech123@localhost/gamesucks'
app.config['JWT_SECRET_KEY'] = 'secret_key'


db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
jwt = JWTManager(app)

api = Api(app)

# Cek jika token adalah milik admin
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'admin':
            # Jika bukan admin
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # Jika admin
            return fn(*args, **kwargs)
    return wrapper

# Cek claims di token adalah pelapak
def pelapak_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'pelapak':
            # Bukan pelapak, atau Admin, or guest -> tidak dapat masuk
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # Welcoming Pelapak
            return fn(*args, **kwargs)
    return wrapper

# Model Users: users data, admin or pelapak
class Users(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String(255), nullable= False)
    username = db.Column(db.String(255), nullable= False)
    email = db.Column(db.String(255), unique= True, nullable= False)
    password = db.Column(db.String(255), nullable= False)
    phone = db.Column(db.String(255))
    address = db.Column(db.String(255))
    type = db.Column(db.String(30), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    game =  db.relationship('Game', backref='users')
    transaksi = db.relationship('Transaction', backref='users')

    def __repr__(self):
        return '<Users %r>' % self.id

# Model Game
class Game(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(255), nullable= False)
    studio = db.Column(db.String(255))
    category = db.Column(db.Integer, db.ForeignKey("category.id"), nullable= False)
    price = db.Column(db.Integer, nullable = False)
    stock = db.Column(db.Integer)
    url_picture= db.Column(db.String(255))
    status = db.Column(db.String(255))
    description = db.Column(db.String(2000))
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    #Foreign Key
    pelapak_id= db.Column(db.Integer, db.ForeignKey("users.id"), nullable= False)
    transaksi_detail =  db.relationship('TransactionDetail', backref='game')

    def __repr__(self):
        return '<Game %r>' % self.id



class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    user_id= db.Column(db.Integer, db.ForeignKey("users.id"), nullable= False)
    total_price = db.Column(db.Integer, default= 0)
    total_qty = db.Column(db.Integer, default= 0)
    status = db.Column(db.Boolean, default= False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    transaksi_detail = db.relationship('TransactionDetail', backref='transaction')

    def __repr__(self):
        return '<Transaction %r>' % self.id

class TransactionDetail(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    transaksi_id = db.Column(db.Integer, db.ForeignKey("transaction.id"), nullable= False)
    item_id = db.Column(db.Integer, db.ForeignKey("game.id"), nullable= False)
    price = db.Column(db.Integer, nullable = False)
    qty = db.Column(db.Integer, nullable = False)
    status = db.Column(db.Boolean, default= True)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())

    def __repr__(self):
        return '<TransactionDetail %r>' % self.id



class Category(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    category = db.Column(db.String(255), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    game = db.relationship("Game", backref='category_game')

    def __repr__(self):
        return '<Category %r>' % self.id



# Resource to get the JWT token 
class LoginResource(Resource):
    # auth, hanya user dengan token pelapak bisa akses 
    @pelapak_required
    def get(self):
        # get user identity from token by claims 
        current_user = get_jwt_identity()

        # cari data user by user identity (id users dari token by claims)
        qty= Users.query.get(current_user)
        data = {
            "name": qty.name,
            "username": qty.username,
            "email": qty.email,
            "password": qty.password,
            "phone": qty.phone,
            "address": qty.address
        }
        return data, 200

    # method untuk get jwt token untuk pelapak yang sudah memiliki akun
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', location= 'json', required= True)
        parser.add_argument('password', location= 'json', required= True)

        args = parser.parse_args()

        # get data users by username and password
        qry = Users.query.filter_by( username= args['username'], password= args['password']).first()
        
        # cek username dan password?
        if qry == None:
            # if not return 401
            return {"message": "Unauthorized Access"}, 401
        
        # membuat token untuk akun
        token = create_access_token(identity= qry.id, expires_delta = datetime.timedelta(days=1))

        # return token
        return {"token": token}, 200




# Resource untuk register account
class RegisterResource(Resource):
    def post(self):
        # collect data from body 
        parser = reqparse.RequestParser()
        parser.add_argument('name', type= str, location='json', required= True, help= 'name must be string and exist')
        parser.add_argument('username', type= str, location='json', required= True, help= 'username must be string and exist')
        parser.add_argument('email', type= str, location='json', required= True, help= 'email must be string and exist')
        parser.add_argument('password', type= str, location='json', required=True, help= 'password must be string and exist')
        parser.add_argument('address', type= str, location='json', required=True, help= 'address must be string and exist')
        parser.add_argument('phone', type= str, location='json', required=True, help= 'phone must be string and exist')
        parser.add_argument('secret', type= str, location='json', required=False, help= 'secret must be string')

        mySecret = "ADMIN"
        # parse it in args variable
        args = parser.parse_args()

        # find user data by username
        qry= Users.query.filter_by(username= args['username']).first()
        # if username already taken
        if qry != None:
            # tell him that the username already taken
            return {"message": "Username has been taken"}, 406

        # cek by email
        qry= Users.query.filter_by(email= args['email']).first()
        if qry != None:
            # notify
            return {"message": "Email has been taken"}, 406

        # if username and email available then check its admin or pelapak
        if(args["secret"] != None and args["secret"] == mySecret):
            auth = 'admin'
        else:
            auth = 'pelapak'

        data = Users(
                name= args['name'], 
                username= args['username'], 
                email= args['email'], 
                password= args['password'], 
                address= args['address'], 
                phone= args['phone'], 
                type= auth
            )

        db.session.add(data)
        # insert it to database 
        db.session.commit()

        # create token
        token = create_access_token(identity= data.id, expires_delta = datetime.timedelta(days=1))
        # return token
        return {"message": "Success" , "token": token}, 200

# create claims to user token
@jwt.user_claims_loader
def add_claim_to_access_token(identity):
    # find users data by identity field in token
    data = Users.query.get(identity)
    # add 'type' as key and type from db as value 
    return { "type": data.type }



class PelapakResource(Resource):
    # field yang ingin di tampilkan lewat marshal
    game_field= {
        "id": fields.Integer,
        "title": fields.String, 
        "studio": fields.String,
        "category_game.category": fields.String,
        "price": fields.Integer,
        "stock": fields.Integer,
        "url_picture": fields.String,
        "status": fields.String,
        "description": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "users.name": fields.String
    }
    
    @pelapak_required
    def get(self, id= None):
        # get identity from user token
        current_user = get_jwt_identity()

        ans = {}
        ans["message"] = "SUCCESS"
        rows = []

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Game.query.filter_by(pelapak_id = current_user, id = id).first()
            # if data not found
            if(qry == None):
                # return message
                return {'message': 'Data not found !'}, 404
            # if data has been found
            rows = marshal(qry, self.game_field)
            ans["data"] = rows
            # return data
            return ans, 200

        # get all data by current user token 
        qry = Game.query.filter_by(pelapak_id = current_user)
        
        for row in qry.all():
            # append data to rows
            rows.append(marshal(row, self.game_field))
        
        ans["data"] = rows

        # return all data
        return ans, 200

    @pelapak_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("title", type= str, help= 'title key must be an string and exist', location= 'json', required= True)
        parser.add_argument("studio", type= str, help= 'studio must be an string and exist', location= 'json', required= True)
        parser.add_argument("category", type= str, help= 'category must be an string and exist', location= 'json', required= True)
        parser.add_argument("price", type= int, help= 'price must be an integer and exist', location= 'json', required= True)
        parser.add_argument("stock", type= int, help= 'stock must be an integer and exist', location= 'json', required= True)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False, default= 'default pict')
        parser.add_argument("status", type= str, help= 'status must be an string', location= 'json', required= False, default= 'show')
        parser.add_argument("description", type= str, help= 'put your description', location= 'json', required= False)

        args = parser.parse_args()

        # get identity from token
        current_user = get_jwt_identity()

        # insert all data
        data = Game(
                title= args["title"],
                studio= args["studio"],
                category= args["category"],
                price= args["price"],
                stock= args["stock"],
                url_picture= args["url_picture"],
                status= args["status"],
                description= args["description"],
                pelapak_id= current_user
            )
        db.session.add(data)
        db.session.commit()

        return {"message": "Success"}, 200

    @pelapak_required
    def patch(self, id):
        # get identity from token
        current_user = get_jwt_identity()
        # get data where on id
        data = Game.query.filter_by(pelapak_id = current_user, id = id).first()

        # if data not found
        if(data == None): 
            # return not found
            return {'message': 'Data not found !'}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("title", type= str, help= 'title key must be an string and exist', location= 'json', required= False)
        parser.add_argument("studio", type= str, help= 'studio must be an string and exist', location= 'json', required= False)
        parser.add_argument("category", type= str, help= 'category must be an string and exist', location= 'json', required= False)
        parser.add_argument("price", type= int, help= 'price must be an integer and exist', location= 'json', required= False)
        parser.add_argument("stock", type= int, help= 'stock must be an integer and exist', location= 'json', required= False)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False)
        parser.add_argument("status", type= str, help= 'status must be an string', location= 'json', required= False)
        parser.add_argument("description", type= str, help= 'put your description', location= 'json', required= False)

        args = parser.parse_args()

        # update the data
        if args["title"] != None:
            data.title= args["title"]
        if args["studio"] != None:
            data.studio= args["studio"]
        if args["category"] != None:
            data.category= args["category"]
        if args["price"] != None:
            data.price= args["price"]
        if args["stock"] != None:
            data.stock= args["stock"]
        if args["url_picture"] != None:
            data.url_picture= args["url_picture"]
        if args["status"] != None:
            data.status= args["status"]
        if args["description"] != None:
            data.description= args["description"]

        # update updatedAt field when update data
        data.updatedAt = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"message": "Success"}, 200

    @pelapak_required
    def delete(self, id):
        # get identity from token
        current_user = get_jwt_identity()
        # get data
        data = Game.query.filter_by(pelapak_id = current_user, id = id).first()

        #check if data exist
        if data == None:
            # return not found when nothing was found
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "Success"}, 200




class TransaksiResource(Resource):

    cart_detail_field= {
        "id": fields.Integer,
        "game.id": fields.Integer,
        "game.title": fields.String,
        "qty": fields.Integer,
        "price": fields.Integer,
    }

    cart_field= {
        "id": fields.Integer,
        "total_qty": fields.Integer,
        "total_price": fields.Integer,
        "updatedAt": fields.String
    }


    @pelapak_required
    def get(self):
        current_user = get_jwt_identity()

        parser = reqparse.RequestParser()
        parser.add_argument("status", type= bool, help= 'title key must be string and exist', location= 'args', default= False)
        args = parser.parse_args()
        
        cart = Transaction.query

        if args['status'] == False:
            cart = cart.filter_by(user_id = current_user, status = False).first()
            if cart == None:
                ans = {}
                ans["message"] = "SUCCESS"
                ans["total_qty"] = 0
                ans["total_price"] = 0
                ans["data"] = []
                return ans, 200

            detail = TransactionDetail.query.filter_by(transaksi_id = cart.id, status = True)
            
            ans = {}
            ans["message"] = "SUCCESS"
            ans["total_qty"] = cart.total_qty
            ans["total_price"] = cart.total_price
            rows = []
            for row in detail.all():
                rows.append(marshal(row, self.cart_detail_field))
            
            ans["data"] = rows
            return ans, 200

        elif args['status'] == True:
            cart = cart.filter_by(user_id = current_user, status = True).order_by('updatedAt desc').all()
            
            all_data = []
            for data in cart:
                ans = marshal(data, self.cart_field)
                
                detail = TransactionDetail.query.filter_by(transaksi_id = data.id, status = True)
                rows = []
                for row in detail.all():
                    rows.append(marshal(row, self.cart_detail_field))
                
                ans["datas"] = rows
                all_data.append(ans)
            
            return all_data, 200


    # def get(self):

    #     current_user = get_jwt_identity()
    #     cart = Transaction.query.filter_by(user_id = current_user, status = False).first()

    #     if cart == None:
    #         ans = {}
    #         ans["message"] = "SUCCESS"
    #         ans["total_qty"] = 0
    #         ans["total_price"] = 0
    #         ans["data"] = []
    #         return ans, 200

    #     detail = TransactionDetail.query.filter_by(transaksi_id = cart.id, status = True)
        
    #     ans = {}
    #     ans["message"] = "SUCCESS"
    #     ans["total_qty"] = cart.total_qty
    #     ans["total_price"] = cart.total_price
    #     rows = []
    #     for row in detail.all():
    #         rows.append(marshal(row, self.cart_field))
        
    #     ans["data"] = rows
    #     return ans, 200

    
    @pelapak_required
    def post(self, id):

        current_user = get_jwt_identity()
        cart = Transaction.query.filter_by(user_id = current_user, status = False).first()

        if cart == None:
            cart = Transaction(user_id = current_user)
            db.session.add(cart)
            db.session.commit()
        
        price = Game.query.get(id).price
        detail = TransactionDetail.query.filter_by(transaksi_id = cart.id, item_id = id, status = True).first()

        if detail == None:
            detail = TransactionDetail(transaksi_id = cart.id, item_id = id, qty = 1, price = price)
        else:
            detail.qty = detail.qty + 1
            detail.updatedAt = db.func.current_timestamp()
        db.session.add(detail)
        db.session.commit()

        cart.total_qty = cart.total_qty + 1
        cart.total_price = cart.total_price + price
        cart.updatedAt = db.func.current_timestamp()
        db.session.add(cart)
        db.session.commit()

        return {"message": "SUCCESS"}, 200



    @pelapak_required
    def patch(self, id):

        current_user = get_jwt_identity()
        cart = Transaction.query.filter_by(user_id = current_user, status = False).first()

        parser = reqparse.RequestParser()
        parser.add_argument("action", type= str, help= 'action does not exist', location= 'json', choices= ("add_qty", "substract_qty", "pay", "delete"), required= False)
        args = parser.parse_args()

        if args['action'] == "add_qty":
            price = Game.query.get(id).price
            cart.total_qty = cart.total_qty + 1
            cart.total_price = cart.total_price + price
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

            detail = TransactionDetail.query.filter_by(transaksi_id = cart.id, item_id = id, status= True).first()
            detail.qty = detail.qty + 1
            detail.updatedAt = db.func.current_timestamp()
            db.session.add(detail)
            db.session.commit()

        elif args['action'] == "substract_qty":
            price = Game.query.get(id).price
            cart.total_qty = cart.total_qty - 1
            cart.total_price = cart.total_price - price
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

            detail = TransactionDetail.query.filter_by(transaksi_id = cart.id, item_id = id, status= True).first()
            detail.qty = detail.qty - 1
            detail.updatedAt = db.func.current_timestamp()
            db.session.add(detail)
            db.session.commit()

        elif args['action'] == "pay":
            cart.status = True
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

        elif args['action'] == "delete":

            price = Game.query.get(id).price

            detail = TransactionDetail.query.filter_by(transaksi_id = cart.id, item_id = id, status= True).first()
            detail.status = False
            detail.updatedAt = db.func.current_timestamp()
            db.session.add(detail)
            db.session.commit()

            cart.total_qty = cart.total_qty - detail.qty
            cart.total_price = cart.total_price - (detail.qty * price)
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

        return {'message': "SUCCESS"}, 200



class PublicResource(Resource):
    # tampilkan field dengan marshal
    game_field= {
        "id": fields.Integer,
        "title": fields.String, 
        "studio": fields.String,
        "category": fields.String,
        "price": fields.Integer,
        "stock": fields.Integer,
        "url_picture": fields.String,
        "status": fields.String,
        "description": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "pelapak_id": fields.String
    }
    
    def get(self, id = None):

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Game.query.get(id)
            # jika data tidak ditemukan
            if(qry == None):
                # return message
                return {'message': 'Data not found !'}, 404
            # if found data
            ans = {
                "page": 1,
                "total_page": 1,
                "per_page": 25,
                "data": []
            }

            rows = marshal(qry, self.game_field)
            ans["data"] = rows
            # return data
            return ans, 200

        parser = reqparse.RequestParser()
        parser.add_argument("p", type= int, location= 'args', default= 1)
        parser.add_argument("rp", type= int, location= 'args', default= 25)
        # query filter
        parser.add_argument("id",type= int, help= 'id must be an integer', location= 'args')
        parser.add_argument("title",type= str, help= 'title must be an string', location= 'args')
        parser.add_argument("studio",type= str, help= 'studio must be an string', location= 'args')
        parser.add_argument("price",type= int, help= 'price must be an integer', location= 'args')
        parser.add_argument("stock",type= int, help= 'stock must be an integer', location= 'args')
        parser.add_argument("category",type= str, help= 'category must be an string', location= 'args')
        # query order
        parser.add_argument("orderBy", help= 'invalid orderBy', location= 'args', choices=('id', 'title', 'status', 'price', 'stock', 'studio', 'category', 'createdAt', 'updatedAt'))
        parser.add_argument("sort", help= 'invalid sort value', location= 'args', choices=('asc', 'desc'), default = 'asc')

        args = parser.parse_args()

        qry = Game.query

        if args['p'] == 1:
            offset = 0
        else:
            offset = (args['p'] * args['rp']) - args['rp']

        # query where
        if args['id'] != None:
            qry = qry.filter_by(id = args['id'])
        if args["title"] != None:
            qry = qry.filter_by(title = args["title"])  
        if args["studio"] != None:
            qry = qry.filter_by(studio = args["studio"]) 
        if args["category"] != None:
            qry = qry.filter_by(category = args["category"]) 
        if args["price"] != None:
            qry = qry.filter_by(price = args["price"]) 
        if args["stock"] != None:
            qry = qry.filter_by(stock = args["stock"]) 

           
        qry = qry.filter_by(status = "show")
        # query orderBy
        if args['orderBy'] != None:

            if args["orderBy"] == "id":
                field_sort = Game.id
            elif args["orderBy"] == "status":
                field_sort = Game.status
            elif args["orderBy"] == "price":
                field_sort = Game.price
            elif args["orderBy"] == "stock":
                field_sort = Game.stock
            elif args["orderBy"] == "studio":
                field_sort = Game.studio
            elif args["orderBy"] == "category":
                field_sort = Game.category
            elif args["orderBy"] == "createdAt":
                field_sort = Game.createdAt
            elif args["orderBy"] == "updatedAt":
                field_sort = Game.updatedAt

            if args['sort'] == 'desc':
                qry = qry.order_by(desc(field_sort))
               
            else:
                qry = qry.order_by(field_sort)

        # query limit dan pagination
        
        rows= qry.count()
        qry =  qry.limit(args['rp']).offset(offset)
        tp = math.ceil(rows / args['rp'])
        
        ans = {
            "page": args['p'],
            "total_page": tp,
            "per_page": args['rp'],
            "data": []
        }

        rows = []
        for row in qry.all():
            rows.append(marshal(row, self.game_field))

        ans["data"] = rows

        return ans, 200

class CategoryResource(Resource):
    category_field = {
        "id" : fields.Integer,
        "category" : fields.String,
        "createdAt" : fields.String,
        "updatedAt" : fields.String
    }

    def get(self):
        data = Category.query
        ans = {
            "message": "SUCCESS",
            "data": []
        }

        rows = []
        for row in data.all():
            rows.append(marshal(row, self.category_field))
        ans["data"] = rows
        return ans, 200
        
    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= 'category must be sstring and exist', location= 'json', required= True)
        
        args = parser.parse_args()

        data = Category.query.filter_by(category = args["category"]).first()
        if (data != None):
            return {"message": "System cannot have duplicate category"}, 406

        data = Category(
                category= args["category"],
            )
        db.session.add(data)
        db.session.commit()

        return {"message": "Success"}, 200
    
    @admin_required
    def patch(self, id):
        data = Category.query.get(id)

        if(data == None):
            return {"message": "Data not found!"}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("category", type= str, help= 'category string and exist', location= 'json', required= True)
        
        args = parser.parse_args()
        data.category = args['category']
        db.session.add(data)
        db.session.commit()

        return {"message": "Success"}, 200

    @admin_required
    def delete(self, id):
        data = Category.query.get(id)

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "Success"}, 200


# Users Endpoint
api.add_resource(LoginResource, '/api/users/login', '/api/users/me')
api.add_resource(RegisterResource, '/api/users/register')

# Pelapak Endpoint
api.add_resource(PelapakResource, '/api/users/items', '/api/users/items/<int:id>')

# Transaksi Endpoint
api.add_resource(TransaksiResource, '/api/users/transaction', '/api/users/transaction/<int:id>')

# Public Endpoint
api.add_resource(PublicResource, '/api/public/items', '/api/public/items/<int:id>' )

# Kategori Endpoint
api.add_resource(CategoryResource, '/api/public/category', '/api/public/category/<int:id>' )

@jwt.expired_token_loader
def exipred_token_message():
    return json.dumps({"message": "The token has expired"}), 401, {'Content-Type': 'application/json'}

@jwt.unauthorized_loader
def unathorized_message(error_string):
    return json.dumps({'message': error_string}), 401, {'Content-Type': 'application/json'}


if __name__ == "__main__":
    try:
        if sys.argv[1] == 'db':
            manager.run()
    except IndexError as identifier:
        app.run(debug=True, host='0.0.0.0', port=5000)