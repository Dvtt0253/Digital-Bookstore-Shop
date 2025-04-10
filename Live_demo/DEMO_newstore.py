from flask import Flask, render_template, url_for, redirect, request, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from argon2.exceptions import VerifyMismatchError
from argon2 import PasswordHasher
import secrets
import string
from datetime import datetime, timedelta
import smtplib
import os
import dotenv
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import paypalrestsdk
from firewall_lib.flask_firewall import Firewall

# Copyright (c) 2025 Joie Harvey
# All Rights Reserved.
#
# Licensed under the All Rights Reserved. Unauthorized use or redistribution is prohibited.


"""SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
sender_email = os.getenv('EMAIL')
email_password = os.getenv('EMAIL_PASSWORD')

dotenv.load_dotenv()"""



app = Flask(__name__)



firewall = Firewall(60, 60)
firewall.startTempBlacklist_removal()
firewall.startperiodic_check()





app.secret_key = secrets.token_hex(32)
ph = PasswordHasher()

paypalrestsdk.configure({
    "mode" : "sandbox",
    "client_id" : "ASoDBYP69_rSN5_OtvkRvXE2HfVoyNJGjDgFHO6sVFIASuRAr9hpEnL8jo5GRo_EQjXBRRZKJnL9LcLq",
    "client_secret" : "EDdDhuy9b7ptvbjZxRBH9t4-8PDgSTalix0_BTxd7iPp5h0N0CoC_-348FU4MuxzyKCBdjcQcOImd6ck"
})

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///users.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_BINDS'] = {
    'books_db': 'sqlite:///books.db',
    'cart_db': 'sqlite:///cart.db',
    'orders_db': 'sqlite:///order.db',
    'tokens_db':'sqlite:///tokens.db',
    'Demouser_db':'sqlite:///demo_user.db',
    'Demoorder_db':'sqlite:///demo_order.db'


}

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.Text, nullable=False)
    last_name = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    hashed_password = db.Column(db.String(300), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=0)
    user_ip = db.Column(db.String(100), nullable=True)
    user_agent = db.Column(db.String(250), nullable=True)
    join_date = db.Column(db.DateTime, nullable=False)

class Book(db.Model):
    __tablename__='books'
    __bind_key__ = 'books_db'
    id = db.Column(db.Integer, primary_key=True)
    book_title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.Text, nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)
    pdf_filename = db.Column(db.String(300), nullable=False)
    book_cover = db.Column(db.String(300), nullable=False)

class Cart(db.Model):
    __tablename__ = 'cart'
    __bind_key__ = 'cart_db'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    book_name = db.Column(db.Text, nullable=False)
    book_author = db.Column(db.Text, nullable=False)
    book_price = db.Column(db.Numeric(10,2), nullable=False)
    book_coverimage = db.Column(db.String(200), nullable=False)
    deleted = db.Column(db.Boolean, nullable=False, default=0)
    item_id = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    __tablename__ = 'orders'
    __bind_key__ = 'orders_db'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    item_title = db.Column(db.Text, nullable=False)
    item_author = db.Column(db.Text, nullable = False)
    total_price = db.Column(db.Numeric, nullable=False)
    item_id = db.Column(db.Integer, nullable=False)
    book_image = db.Column(db.String(250), nullable=False)
    book_file = db.Column(db.String(300), nullable=False)

class Demo_order(db.Model):
    __tablename__ = 'demo_order'
    __bind_key__ = 'Demoorder_db'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    item_title = db.Column(db.Text, nullable=False)
    item_author = db.Column(db.Text, nullable = False)
    total_price = db.Column(db.Numeric, nullable=False)
    item_id = db.Column(db.Integer, nullable=False)
    book_image = db.Column(db.String(250), nullable=False)
    book_file = db.Column(db.String(300), nullable=False)

class Token(db.Model):
    __tablename__ = 'tokens'
    __bind_key__ = 'tokens_db'
    id = db.Column(db.Integer, primary_key=True)
    verification_token = db.Column(db.String(200), nullable=False, unique=True )
    issued_time = db.Column(db.DateTime, nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

class Demo_user(db.Model):
    __tablename__ = 'demo_user'
    __bind_key__ = 'Demouser_db'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.Text, nullable=False)
    last_name = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    hashed_password = db.Column(db.String(300), nullable=False)
    join_date = db.Column(db.DateTime, nullable=False)




    






with app.app_context():
    db.create_all()


# adding self to whitelist and removing virtual machine from whitelist for testing purposes

firewall.add_to_whitelist('10.0.0.91', "Personal IP address/creator.")
firewall.add_to_whitelist('127.0.0.1', "Personal local host IP address.")
firewall.remove_from_whitelist('10.0.0.91')


def verify_password(password):
    special_characters = ['!', '?', '%', '>', '<',':', ';', '-', '_', '/', '(', ')', '[', ']', '{','}', '&', '$', '@']
    

    if len(password) >= 8 and any (character in password for character in special_characters) and any(char.isdigit() for char in password):
        return True
    else:
        return False


def generate_csrf_token():
    
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


def create_token(length):
    alphabet = string.ascii_letters + string.digits

    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    return token

"""def send_verificationemail(email, token, subject, html):
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        html_content = render_template(html, verify_token=token)
        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(sender_email, email_password)
            server.sendmail(sender_email, email , msg.as_string())
    except Exception as e:
        print(f"Error while sending email {e}")

def send_code(email, code, subject):
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        html_content = render_template('confirmation_code.html', code=code)
        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(sender_email, email_password)
            server.sendmail(sender_email, email , msg.as_string())
    except Exception as e:
        print(f"Error while sending email {e}")

def get_device_info():
    user_agent = request.headers['User-Agent']
    start = user_agent.find('(') + 1
    end = user_agent.find(')')
    
    if start > 0 and end > start:
         device_info = user_agent[start:end]
    else: 
        device_info = user_agent

    return device_info"""
    






@app.route('/')
def reroute():

    is_blocked = firewall.block_access()

    if is_blocked == 403:
         return render_template('403_page.html'), 403


    rate_limiting_response = firewall.rate_limiter()

    if rate_limiting_response == 429:
        return render_template('requests_429.html'), 429
    else:
        return redirect(url_for('signup_page'))

    
    
    
     


@app.route('/signup')
def signup_page():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
         return render_template('403_page.html'), 403
    return render_template('Create_account.html')

@app.route('/create_account', methods=['POST'])
def create_account():

    
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    ratelimiting_response = firewall.rate_limiter()
    if ratelimiting_response == 429:
        return render_template('requests_429.html'), 429
    
    first_name = firewall.santitize_input(request.form['first_name'])

    if firewall.identify_payloads(first_name) == 403:
        return render_template('malicious_403.html'), 403
    
    last_name = firewall.santitize_input(request.form['last_name'])

    if firewall.identify_payloads(last_name) == 403:
        return render_template('malicious_403.html'), 403
    email = firewall.santitize_input(request.form['email'].lower())

    if firewall.identify_payloads(email) == 403:
        return render_template('malicious_403.html'), 403
    
    users_token = create_token(32)
    token_created = datetime.now()
    token_expiry = token_created + timedelta(hours=24)
    new_user = Demo_user.query.filter_by(email=email).first()

    """subject = "Verify Your ShelfSpace Email Address!"
    html = 'redirect_verify.html'

    

    send_verificationemail(email, users_token, subject, html)"""

    
    
    


   
    hashed_password = firewall.santitize_input(ph.hash(request.form['password']))
    if firewall.identify_payloads(hashed_password) == 403:
        return render_template('malicious_403.html'), 403
    signup_date = datetime.now()

    try:
        

            new_user = Demo_user(first_name=first_name, last_name=last_name, email=email, hashed_password=hashed_password, join_date=signup_date)

            db.session.add(new_user)
            db.session.commit()
           
        
    
    except IntegrityError:
        db.session.rollback()
        flash("Email already exists. Please sign into your account.", category="error")
        return redirect(url_for('signup_page'))
    

    new_token = Token(verification_token=users_token, issued_time=token_created, expiry_date=token_expiry, user_id=new_user.id)
    db.session.add(new_token)
    db.session.commit()

    

    
   
    return render_template('login.html')

    


    


@app.route('/login_page')
def login_page():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403
    return render_template('login.html')

@app.route('/auth', methods=['POST', 'GET'])
def authenticate():

   
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403
    






    if request.method == 'POST':
        returning_email= firewall.santitize_input(request.form['login-email'].lower())
        if firewall.identify_payloads(returning_email) == 403:
            return render_template('malicious_403.html'), 403
        loginlimit_response = firewall.login_limiter( 5, 60)
        if loginlimit_response == 403:
            is_blocked = firewall.block_access()
            if is_blocked == 403:
              
          
                
                return render_template('loginattempts_403.html'), 403
            
            

               

        returning_password = firewall.santitize_input(request.form['login-password'])
        if firewall.identify_payloads(returning_password) == 403:
            return render_template('malicious_403.html'), 403
        returning_user = Demo_user.query.filter_by(email=returning_email).first()

       

        if returning_user:
            #if returning_user.is_verified == 1:
                try:
                    ph.verify(returning_user.hashed_password, returning_password)

                except VerifyMismatchError as e:
                    db.session.rollback()
                    flash("Incorrect password, Try again.", category="error")
                    return redirect(url_for('login_page'))
                """if returning_user.user_ip is None and returning_user.user_agent is None:

                    user_ip = request.remote_addr
                    user_agent = get_device_info()
                    returning_user.user_ip = user_ip
                    returning_user.user_agent = user_agent
                    db.session.commit()
                else:
                    current_ip = request.remote_addr
                    current_agent = request.headers['User-Agent']
                    if returning_user.user_ip != current_ip: #or returning_user.user_agent != current_agent:
                        session['attempt_id'] = returning_user.id
                        code = str(random.randint(100000,999999))
                        subject = "New Device Login Attempt on ShelfSpace: Verify Your Identity"
                        send_code(returning_email, code, subject)
                        return render_template('fradulent_login.html', code=code)"""
                    
                csrf_token = generate_csrf_token()
                        
                session['first_name'] = returning_user.first_name
                session['last_name'] = returning_user.last_name
                session['email'] = returning_user.email
                session['id'] = returning_user.id
                session['csrf'] = csrf_token
               
                return redirect(url_for('product_homepage'))
            #else:
                flash("Please verify your email address.", category="error")
                return redirect(url_for('login_page'))
        else:
            flash("User not found", category="error")
            return redirect(url_for('signup_page'))


@app.route('/product_homepage')
def product_homepage():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
       return render_template('403_page.html'), 403
    ratelimiting_response = firewall.rate_limiter()
    
    books_list = Book.query.all()
    cart_list = Cart.query.filter_by(user_id=session['id'])
    if ratelimiting_response == 429:
        return render_template('requests_429.html'), 429
    else:
        return render_template('homepage.html',books=books_list, firstname=session['first_name'], cart=cart_list, total=TotalPrice(), user_id=session['id'])

@app.route('/addtocart', methods=['POST', 'GET'])
def addtocart():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403
    if request.method == 'POST':
        chosen_bookid = request.form['bookid']
        book_incart = Book.query.filter_by(id=chosen_bookid).all()
        for book in book_incart:

            book_name = book.book_title
            book_author = book.author
            book_price = book.price
            book_image = book.book_cover
            user_id = session['id']
            item_id = book.id

            new_cartitem = Cart(user_id=user_id, book_name=book_name, book_author=book_author, book_price=book_price, book_coverimage=book_image, item_id=item_id)
        db.session.add(new_cartitem)
        db.session.commit()
        flash(f"\"{book_name}\" has been successfully added to your cart!", category="success")
        return redirect(url_for('product_homepage'))
    

def TotalPrice():
    cart_items = Cart.query.filter_by(user_id=session['id']).all()
    total_price = 0
    for item in cart_items:
        total_price += item.book_price
    
    return total_price


@app.route('/deleted_item', methods=['POST', 'GET'])
def delete_item():
    if request.method == 'POST':
        deleted_bookid = request.form['deletedbook_id']

        if deleted_bookid:
            deleted_book = Cart.query.filter_by(item_id=deleted_bookid).first()
        if deleted_book:
            deleted_book.deleted = 1
        removed_books = Cart.query.filter_by(deleted=1).all()
        for book in removed_books:
            db.session.delete(book)
            db.session.commit()
            return redirect (url_for('product_homepage'))


@app.route('/checkout')
def checkout():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403
    checkout_items = Cart.query.filter_by(user_id=session['id'])
    return render_template('checkout.html',items=checkout_items, total=TotalPrice() )

@app.route('/payment')
def payment():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403
    
    return render_template('payment.html', total=TotalPrice())



@app.route('/verify_payment', methods=['POST'])
def verify_payment():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    payment_id = request.json.get('paymentID')
    payer_id = request.json.get('payerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}): 
        return jsonify({"status": "Payment successfull"}), 200

        
    else:
        return jsonify({"status": "Payment failed"}), 400
    

@app.route('/download_link')
def download_link():
    ordered_item = Cart.query.filter_by(user_id=session['id']).all()
    purchased_bookfiles = []
    for item in ordered_item:
        bought_book = Book.query.filter_by(id=item.item_id).first()
        if bought_book:
            purchased_bookfiles.append(bought_book)
        new_order = Demo_order(item_title=item.book_name, book_file=bought_book.pdf_filename, item_author=item.book_author, total_price=TotalPrice(), user_id=session['id'], item_id=item.item_id, book_image=item.book_coverimage)
        db.session.add(new_order)
        db.session.commit()


    """try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = session['email']
        msg['Subject'] = "Your Order from ShelfSpace has been Processed! Your Downloadable files are included below!"
        html_content = render_template('email.html', purchased_books=purchased_bookfiles, items=ordered_item, total=TotalPrice())
        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(sender_email, email_password)
            server.sendmail(sender_email, session['email'] , msg.as_string())
    except Exception as e:
        print(f"Error while sending email {e}")"""


    return render_template('download.html', purchased_books=purchased_bookfiles, items=ordered_item, total=TotalPrice())

@app.route('/order_shelf')

    
def order_shelf():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    orders = Demo_order.query.filter_by(user_id=session['id'])
    return render_template('ordershelf.html',orders=orders, firstname=session['first_name'] )

@app.route('/viewaccount')
def view_account():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    ratelimiting_response = firewall.rate_limiter()
    user = Demo_user.query.filter_by(id=session['id']).first()
    signup_date= user.join_date
    formattedjoin_date = signup_date.strftime("%B %d, %Y")

    if ratelimiting_response == 429:
        return render_template('requests_429.html'), 429
    else:

        return render_template('manageaccount.html', csrf_token=session['csrf'], user_id=session['id'], firstname=session['first_name'], lastname=session['last_name'], email=session['email'], joindate=formattedjoin_date)

"""@app.route('/change_email', methods=['POST'])
def change_email():
    is_blocked = firewall.block_access()
    is_ratelimited = firewall.rate_limiter()

    if is_blocked == 403:
       return render_template('403_page.html'), 403


   
    if request.method == 'POST':
        if is_ratelimited == 429:
            return render_template('requests_429.html'), 429
        csrf_token = request.form['csrf_token']

        new_email = firewall.santitize_input(request.form['change-email'].lower())
        if firewall.identify_payloads(new_email) == 403:
            return render_template('malicious_403.html'), 403
        if csrf_token:
            if csrf_token == session['csrf']:

                if new_email:
                    user = User.query.filter_by(id=session['id']).first()
                    user.email = new_email
        
                    db.session.commit()
                    flash("Your email has been updated successfully!", category="success")

                    return redirect(url_for('view_account'))
                else:
                    flash("No email entered. Please enter your new email address.", category="error")
                    return redirect(url_for('view_account'))
            else:
                flash("CSRF token is incorrect, request cannot be completed.", category="error")
                return redirect(url_for('view_account'))
        else:
            flash("Missing CSRF  token. Request cannot be completed.", category="error")

@app.route('/change_password')
def change_password():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    return render_template('changepassword.html', csrf_token=session['csrf'])

@app.route('/update_password', methods=['POST'])
def update_password():
    
    is_blocked = firewall.block_access()
    is_ratelimited = firewall.rate_limiter()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    
    if request.method == 'POST':
        if is_ratelimited == 429:
            return render_template('requests_429.html'), 429
        csrf_token = request.form['csrf_token']
        old_password = firewall.santitize_input(request.form['old-password'])
        if firewall.identify_payloads(old_password) == 403:
            return render_template('malicious_403.html'), 403
        new_password = firewall.santitize_input((request.form['updated-password']))
        
           

        if firewall.identify_payloads(new_password) == 403:
            return render_template('malicious_403.html'), 403
        
        
        user = User.query.filter_by(id=session['id']).first()
        if csrf_token:
            if csrf_token == session['csrf']:

                if verify_password(new_password):

                    if user:
                        try:
                            ph.verify(user.hashed_password, old_password)
                        except VerifyMismatchError:
                            db.session.rollback()
                            flash("Previous password is incorrect.")
                            return redirect(url_for('change_password'))
                        
                        
                        user.hashed_password = ph.hash(new_password)
                        db.session.commit()
                        flash("Your password has been updated successfully!", category="success")
                        return redirect(url_for('view_account'))

                    

                   
                
                    
                    else:
                        flash("User not found", category="error")
                        return redirect(url_for('view_account'))
                else:
                    flash("Password must contain at least 8 characters, one digit, and one special character of the following:!, ?, %, >, <,:, ;, -, _, /, (, ), [, ], {,}, &, $, @ ")
                    return redirect(url_for("change_password"))
            else:
                flash("CSRF token is incorrect. Request could not be completed.", category="error")
                return redirect(url_for('view_account'))
        else:
            flash("CSRF token is missing. Request could not be completed", category="error")
            return redirect(url_for('view_account'))


@app.route('/delete_account')
def delete_account():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
       return render_template('403_page.html'), 403

    return render_template('deleteaccount.html', csrf_token=session['csrf'])

@app.route('/account_deleted', methods=['POST'])
def account_deleted():
    is_blocked = firewall.block_access()
    is_ratelimited = firewall.rate_limiter()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    
    if request.method == 'POST':
        if is_ratelimited == 429:
            return render_template('requests_429.html'), 429
        csrf_token = request.form['csrf_token']
        email = firewall.santitize_input(request.form['deleteaccount-email'])
        if firewall.identify_payloads(email) == 403:
            return render_template('malicious_403.html'), 403
        password = firewall.santitize_input(request.form['deleteaccount-password'])
        if firewall.identify_payloads(password) == 403:
            return render_template('malicious_403.html'), 403
        user = User.query.filter_by(email=email).first()
        if csrf_token:
            if csrf_token == session['csrf']:

                 if user:
                    try:
                        ph.verify(user.hashed_password, password)
                    except VerifyMismatchError:
                         db.session.rollback()
                         flash('Incorrect Password', category="error")
                         return redirect(url_for('delete_account'))
                    deleteduser_cart = Cart.query.filter_by(user_id=session['id']).all()
                    deleteduser_orders = Order.query.filter_by(user_id=session['id']).all()
                    for order in deleteduser_orders:
                         db.session.delete(order)
                    for item in deleteduser_cart:
                        db.session.delete(item)
                    db.session.delete(user)
            
                    db.session.commit()
                    flash("Your account has been deleted successfully.")
                    return redirect(url_for('signup_page'))
                 else:
                     flash("User not found.", category="error")
                     return redirect(url_for("view_account"))
            else:
                flash("CSRF token is incorrect. Request could not be completed.", category="error")
                return redirect(url_for('view_account'))
        else:
            flash("CSRF token is missing. Request could not be completed.", category="error")
            return redirect(url_for('view_account'))"""




@app.route('/verification')
def verification():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
       return render_template('403_page.html'), 403

    return render_template('successful_verify.html')


@app.route('/verify_email', methods=['GET','POST'])
def verify_email():
    is_blocked = firewall.block_access()

    if is_blocked == 403:
        return render_template('403_page.html'), 403

    current_date = datetime.now()
    
    token = request.args['token']

    if token:
        print(f"user_token = {token}")
        verified_token = Token.query.filter_by(verification_token = token).first()
        if verified_token:
            print(f"verified_token = {verified_token}")
            if current_date < verified_token.expiry_date:
                verified_user = User.query.filter_by(id=verified_token.user_id).first()
                if verified_user:
                    print(f"user: {verified_user.email}")
                    verified_user.is_verified = 1
                    db.session.commit()
                    flash("Your email has been verified successfully!", category="success")
                    return redirect(url_for('login_page'))
                else:
                    print("user not found")
                        
                    return jsonify({"Error: User not found"})
                    
            else:
                return jsonify({"Error: Token has expired"})
        else:
            return jsonify({"Error: Incorrect Token"})
    else:
        print("Token not found")
        return jsonify({"Error: Token not found", 404})
    
@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    is_ratelimited = firewall.rate_limiter()
    
    if request.method == 'POST':
        if is_ratelimited == 429:
            return render_template('requests_429.html'), 429
        entered_code = firewall.santitize_input(request.form['entered-code'])
        if firewall.identify_payloads(entered_code) == 403:
            return render_template('malicious_403.html'), 403
        verification_code = request.form['verification-code']
        if entered_code == verification_code:
            confirmed_user = User.query.filter_by(id=session['attempt_id']).first()
            csrf_token = generate_csrf_token()
          
            session['first_name'] = confirmed_user.first_name
            session['last_name'] = confirmed_user.last_name
            session['email'] = confirmed_user.email
            session['id'] = confirmed_user.id
            session['csrf'] = csrf_token
                
            
            return redirect(url_for('product_homepage'))
        else:
            flash('Incorrect code, try again', category="error")
            return render_template('fradulent_login.html', code=verification_code)
        

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        
       
        if 'id' in session and session['id'] == int(user_id):  
            session.pop('id', None) 
            session.clear()
            flash("You have been logged out successfully!", category="success")
            return redirect(url_for('login_page'))  
        else:
            flash("You are not logged in or session mismatch.", category="error")
            return redirect(url_for('login_page'))

    
    return redirect(url_for('login_page'))  

"""@app.route('/reset_page')
def reset_page():
    
    if request.method == 'POST':
        rate_response = firewall.rate_limiter()
        
        if rate_response == 429:
            return render_template('requests_429.html')

    return render_template('reset_password.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    
    
    if request.method == 'POST':
        rate_response = firewall.rate_limiter()
        
        if rate_response == 429:
            return render_template('requests_429.html')
        email = firewall.santitize_input(request.form['email'])
        if firewall.identify_payloads(email) == 403:
            return render_template('mailicious_403.html')
        returning_user = User.query.filter_by(email=email).first()
        
        if returning_user:
            token = create_token(32)
            
            subject = "Verify Your Identity to Reset Your Password"
            html ='verify_reset.html'
            send_verificationemail(returning_user.email,token,subject, html)
            session['reset_token'] = token
            session['reset_id'] = returning_user.id
        flash("If the email you entered matches our records, we will send you a link to reset your password. Please check your email to continue.", category="success")
        return render_template('reset_password.html')
       



@app.route('/verify_reset', methods=['GET', 'POST'])
def verify_reset():
    submitted_token = request.args['token']
    if submitted_token:
        if submitted_token == session['reset_token']:
            csrf_token = generate_csrf_token()
            session['reset_csrf'] = csrf_token
            return render_template('reset_passwordform.html', csrf=csrf_token)
   
        else:
            return "Incorrect Token.", 400
    else:
        return "No access token found", 400



@app.route('/reset', methods=['GET','POST'])
def reset():
    
    if request.method == "POST":
        rate_response = firewall.rate_limiter()
        if rate_response == 429:
            return render_template('requests_429.html')
        new_password = firewall.santitize_input(request.form['new-password'])
        if firewall.identify_payloads(new_password) == 429:
            return render_template('malicious_403.html')
        confirmed = firewall.santitize_input(request.form['confirm-new'])
        if firewall.identify_payloads(confirmed) == 429:
            return render_template('malicious_403.html')
        csrf_token = request.form['csrf_token']

        if csrf_token:
            if csrf_token == session['reset_csrf']:


                if new_password == confirmed:
                    user_reset = User.query.filter_by(id=session['reset_id']).first()
                    if user_reset:
                        user_reset.hashed_password = ph.hash(new_password)
                        db.session.commit()
                        flash("Your password has been successfully reset! However, if you have been temporarily banned due to too many failed login attempts. Please wait until your temporary ban expires before attempting to log in again.", category="success") 
                        return render_template('reset_passwordform.html', csrf=session['reset_csrf'])
                          
                            
                                                                                                
                        
                    else:
                        flash("User not found.", category="error")
                        return render_template('reset_passwordform.html', csrf=session['reset_csrf'] )

                else:
                    flash("Passwords do not match.", category="error")
                    return render_template('reset_passwordform.html', csrf=session['reset_csrf'])
            else: 
                flash("CSRF token is incorrect. Request cannot be completed.")
                return render_template('reset_passwordform.html', csrf=session['reset_csrf'])
        else:
            flash("No CSRF token Found. Request denied. ", category="error")
            return render_template('reset_passwordform.html', csrf=session['reset_csrf'])"""





    






   

        


        
        

    




    



    





            
    





if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5003)