from flask import Flask, flash, render_template, url_for,request,flash,session, redirect
from flask_bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField, BooleanField, DateField, SelectField
from wtforms import IntegerField, TextAreaField, FileField, ValidationError
from wtforms.validators import Required, Email, Length, Regexp,EqualTo, Optional
from flask_wtf.file import FileField, FileRequired, FileAllowed
import os
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
import pymysql
from flask_uploads import send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from itsdangerous import URLSafeTimedSerializer
from flask_login import LoginManager, login_user,current_user,current_user,logout_user,login_required
from flask_uploads import UploadSet, IMAGES, configure_uploads

from flask_wtf.csrf import CSRFProtect,CSRFError
from werkzeug import secure_filename
from threading import Thread





app = Flask(__name__)
bootstrap = Bootstrap(app)



csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'signin'
login_manager.session_protection="Strong"
#login_serializer=URLSafeTimedSerializer



app.config['SECRET_KEY']=os.environ.get('ONLINE_SECRET_KEY')
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('ONLINE_WTF_KEY')
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SECURE'] =False


#email configuration settings

app.config['MAIL_SERVER'] = 'smtp.gmail.com' 
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] =os.environ.get('ONLINE_MAIL_USERNAME') 
app.config['MAIL_PASSWORD'] =os.environ.get('ONLINE_MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER']=os.environ.get('ONLINE_DEFAULT_SENDER')



#database configuarations

app.config['MYSQL_HOST']=os.environ.get('ONLINE_MYSQL_HOST')
app.config['MYSQL_USER']=os.environ.get('ONLINE_MYSQL_USER')
app.config['MYSQL_PASSWORD']= os.environ.get('ONLINE_MYSQL_PASSWORD')
app.config['MYSQL_DB']=os.environ.get('ONLINE_DB_URL')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI']= 'mysql+pymysql://root@localhost/onlinedb?charset=utf8'
app.config['SQLACHEMY_COMMIT_ON_TEARDOWN'] = True
#app.config['USE_UNICODE']=True
#app.config['DEFAULT_CHARSET']='utf8mb4'


app.config['UPLOADS_DEFAULT_DEST'] = '/Users/USER/Desktop/HomeShoppingUg/app/static/images/'
app.config['UPLOADS_DEFAULT_URL'] = 'http://localhost:3030/static/images/'
app.config['UPLOADED_IMAGES_ALLOW'] =['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']

 
app.config['UPLOADED_IMAGES_DEST'] = '/Users/USER/Desktop/HomeShoppingUg/app/static/images/'
app.config['UPLOADED_IMAGES_URL'] = 'http://localhost:3030/static/images/'
images = UploadSet('images', IMAGES)
configure_uploads(app, images)




mail=Mail(app)
db = SQLAlchemy(app)


db.metadata.clear()

class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id=db.Column(db.Integer, primary_key=True)
	admin=db.Column(db.String(64))
	surname=db.Column(db.String(64))
	othernames=db.Column(db.String(64))
	attach_photo = db.Column(db.String(128))
	city=db.Column(db.String(64))
	residence=db.Column(db.String(64))
	mobile_number=db.Column(db.String(64))
	telephone_number=db.Column(db.String(64))
	email=db.Column(db.String(64),unique=True)
	username=db.Column(db.String(64),unique=True)
	password_hash=db.Column(db.Text)

	email_confirmation_sent_on = db.Column(db.DateTime, nullable=True)
	email_confirmed = db.Column(db.Boolean, nullable=True, default=False)
	email_confirmed_on = db.Column(db.DateTime, nullable=True)


	product = db.relationship('Product', backref='user', lazy='dynamic')
	deal = db.relationship('Deal', backref='user', lazy='dynamic')
	order = db.relationship('Order', backref='user', lazy='dynamic')


	@property
	def password(self):
		raise AttributeError('password is not readable')

	@password.setter
	def password(self,password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

	@login_manager.user_loader
	def load_user(user_id):
		return User.query.get(int(user_id))


#Products table

	
		
#electronics model
class Product(db.Model):
	__tablename__='products'
	product_id=db.Column(db.Integer, primary_key=True)
	product_category=db.Column(db.String(64))
	mini_category=db.Column(db.String(64))
	product_name=db.Column(db.String(64))
	product_description=db.Column(db.String(128))
	front_image=db.Column(db.String(128))
	side_image=db.Column(db.String(128))
	hind_image=db.Column(db.String(128))
	real_price=db.Column(db.String(64))
	first_price=db.Column(db.String(64))

	alsobought1=db.Column(db.String(64))
	alsoboughtimage1=db.Column(db.String(128))
	alsobought_description1=db.Column(db.Text)
	alsoboughtreal_price1=db.Column(db.String(64))
	alsoboughtfirst_price1=db.Column(db.String(64))

	alsobought2=db.Column(db.String(64))
	alsoboughtimage2=db.Column(db.String(128))
	alsobought_description2=db.Column(db.Text)
	alsoboughtreal_price2=db.Column(db.String(64))
	alsoboughtfirst_price2=db.Column(db.String(64))

	alsobought3=db.Column(db.String(64))
	alsoboughtimage3=db.Column(db.String(128))
	alsobought_description3=db.Column(db.Text)
	alsoboughtreal_price3=db.Column(db.String(64))
	alsoboughtfirst_price3=db.Column(db.String(64))

	alsobought4=db.Column(db.String(64))
	alsoboughtimage4=db.Column(db.String(128))
	alsobought_description4=db.Column(db.Text)
	alsoboughtreal_price4=db.Column(db.String(64))
	alsoboughtfirst_price4=db.Column(db.String(64))
	date_posted=db.Column(db.DateTime(), default=datetime.utcnow)

	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
	


class Deal(db.Model):
	__tablename__='deals'
	deal_id=db.Column(db.Integer, primary_key=True)
	title=db.Column(db.String(64))
	deal_description=db.Column(db.Text)
	deal_image=db.Column(db.String(128))
	quotes=db.Column(db.Text)

	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Order(db.Model):
	__tablename__='orders'
	order_id=db.Column(db.Integer, primary_key=True)
	product_name=db.Column(db.String(64))
	size=db.Column(db.String(64))
	color=db.Column(db.String(64))
	quantity=db.Column(db.String(64))
	client_name=db.Column(db.String(64))
	mobile_number=db.Column(db.String(64))
	email=db.Column(db.String(64))
	address=db.Column(db.String(64))
	date_posted=db.Column(db.DateTime(), default=datetime.utcnow)

	user_id = db.Column(db.Integer, db.ForeignKey('users.id'))




#db.drop_all()
#db.create_all()



#Forms

class SigninForm(Form):
	username=StringField('Username', validators=[Required()])
	password=PasswordField('Password', validators=[Required()])
	submit=SubmitField('LOGIN')


class SignupForm(Form):
	surname=StringField('Surname', validators=[Required()])
	othernames=StringField('Othernames', validators=[Required()])
	admin=SelectField('Admin', choices=[('Yes','Yes'),('No','No')])
	attach_photo=FileField('Attach Your Photo',validators=[Required()])
	telephone_number=StringField('Telephone Number')
	mobile_number=StringField('Mobile Number')
	username=StringField('Create Username',validators=[Required()])
	email=StringField('Email')
	city=StringField('City', validators=[Required()])
	residence=StringField('Residence')
	password=PasswordField('Password', validators=[Required()])
	password2=PasswordField('Confirm Password')
	submit=SubmitField('LOGIN')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email is Already Registered')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username is Already Taken')


class ProfileForm(Form):
	surname=StringField("Surname",validators=[Required()])
	othernames=StringField("Othernames",validators=[Required()])
	attach_photo=FileField("Change My Profilepicture",validators=[Required()])
	mobile_number=StringField("Mobile Number",validators=[Required()])
	telephone_number=StringField("Talephone Number",validators=[Required()])
	email=StringField("Email",validators=[Required()])
	city=StringField("City",validators=[Required()])
	residence=StringField("Residence",validators=[Required()])
	submit=SubmitField("EDIT PROFILE")



#electronics form
class ElectronicsForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	mini_category=SelectField('Mini Category', choices=[('Woofers','Woofers'),('Fridges','Fridges'),
		('Phones','Phones'),('Otherelectronics','Otherelectronics')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')


#beddings form
class BeddingsForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	mini_category=SelectField('Mini Category', choices=[('Bedsheets','Bedsheets'),('Duvets','Duvets'),
		('Mosquito Nets','Mosquito Nets'),('Pillows','Pillows')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')

#kitchenware form
class KitchenwareForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	mini_category=SelectField('Mini Category', choices=[('Pans','Pans'),('Kitchen Electronics','Kitchen Electronics'),
		('Cutlery','Cutlery'),('Otherkitchenware','Otherkitchenware')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')

#Shoes form
class ShoesForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	mini_category=SelectField('Mini Category', choices=[('Mens','Mens'),('Womens','Womens'),
		('Childrens','Childrens'),('Othershoes','Othershoes')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')

#Clothes form
class ClothesForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	mini_category=SelectField('Mini Category', choices=[('Mens','Mens'),('Womens','Womens'),
		('Childrens','Childrens'),('Otherclothes','Otherclothes')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')

#furniture form
class FurnitureForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	mini_category=SelectField('Mini Category', choices=[('Chairs','Chairs'),('Shoe Racks','Shoe Racks'),
		('Wardrobes','Wardrobes'),('Otherfurniture','Otherfurniture')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')

#general form
class GeneralForm(Form):
	agent_id=IntegerField('Agent Id',validators=[Required()])
	product_category=SelectField('Product Category', choices=[('Electronics','Electronics'),('Beddings','Beddings'),
		('Kitchenware','Kitchenware'),('Shoes','Shoes'),('Clothes','Clothes'),('Furniture','Furniture'),
		('General','General')])
	product_name=StringField('Product Name',validators=[Required()])
	product_description=TextAreaField('Product Description',validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real Price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('POST PRODUCT')


class OrderForm(Form):
	productname=StringField('Product Name*', validators=[Required()])
	color=StringField('Color')
	size=StringField('Size')
	quantity=StringField('Quantity*')
	clientname=StringField('Your Name*', validators=[Required()])
	mobile_number=StringField('Your Mobile Number*', validators=[Required()])
	email=StringField('Your Email')
	address=TextAreaField('Delivery Address*', validators=[Required()])
	submit=SubmitField('ORDER')

class GeneralsearchForm(Form):
	search=StringField('Search',validators=[Required()])
	submit=SubmitField('Search')

class CommentForm(Form):
	name=StringField('Name*', validators=[Required()])
	mobile_number=StringField('Mobile Number*', validators=[Required()])
	email=StringField('Email')
	concern=TextAreaField('Your Concern*', validators=[Required()])
	submit=SubmitField('FORWARD')

class EdititemForm(Form):
	product_name=StringField('Product Name', validators=[Required()])
	product_description=TextAreaField('Product Description', validators=[Required()])
	front_image=FileField('Front Image',validators=[Required()])
	real_price=StringField('Real price',validators=[Required()])
	first_price=StringField('First Price')
	submit=SubmitField('Edit')

class BonusitemForm(Form):
	alsobought=StringField('Bundle Item', validators=[Required()])
	alsobought_image=FileField('Item Image', validators=[Required()])
	alsobought_description=TextAreaField('Product Description',validators=[Required()])
	alsoboughtreal_price=StringField('Real Price',validators=[Required()])
	alsoboughtfirst_price=StringField('First Price')
	submit=SubmitField('Add Item')

class SideimageForm(Form):
	side_image=FileField('Side Image', validators=[Required()])
	submit=SubmitField('Add')

class HindimageForm(Form):
	hind_image=FileField('Side Image', validators=[Required()])
	submit=SubmitField('Add')

class DealForm(Form):
	agent_id=StringField('Agent ID', validators=[Required()])
	title=StringField('Deal title')
	deal_description=TextAreaField('Deal Description')
	deal_image=FileField('Deal Image')
	submit=SubmitField('POST')

class EmailForm(Form):
	email=StringField('Enter Your Email', validators=[Required()])
	submit=SubmitField('SUBMIT')

class PasswordForm(Form):
	password=PasswordField('Enter New Password', validators=[Required()])
	submit=SubmitField('SUBMIT')



#sending mail thread

def send_async_email(msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, text_body, html_body):
    msg = Message(subject, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    thr = Thread(target=send_async_email, args=[msg])
    thr.start()

#password reset
def send_password_reset_email(user_email):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
 
    password_reset_url = url_for(
        'reset_with_token',
        token = password_reset_serializer.dumps(user_email, salt='password-reset-salt'),
        _external=True)
 
    html = render_template(
        'email_password_reset.html',
        password_reset_url=password_reset_url)
 
    send_email('Password Reset Requested', 
    	[user_email],
    	password_reset_url,
    	render_template('email_password_reset.html',password_reset_url=password_reset_url)
     )


@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first_or_404()
        except:
            flash('Invalid email address!', 'error')
            return render_template('password_reset_email.html', form=form)
         
        if user.email_confirmed:
            send_password_reset_email(user.email)
            flash('Please check your email for a password reset link.', 'success')
        else:
            flash('Your email address must be confirmed before attempting a password reset.', 'error')
        return redirect(url_for('signin'))
 
    return render_template('password_reset_email.html', form=form)



@app.route('/reset/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = password_reset_serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('signin'))
 
    form = PasswordForm()
 
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=email).first_or_404()
        except:
            flash('Invalid email address!', 'error')
            return redirect(url_for('signin'))
 
        user.password = form.password.data
        db.session.add(user)
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('signin'))
 
    return render_template('reset_password_with_token.html', form=form, token=token)




@app.route('/')
def index():
	form=GeneralsearchForm()
	if form.validate_on_submit():
		pass
	minipans=Product.query.filter_by(mini_category='Pans').all()
	minicutlery=Product.query.filter_by(mini_category='Cutlery').all()
	minikitchenelectronics=Product.query.filter_by(mini_category='Kitchen Electronics').all()
	otherkitchenware=Product.query.filter_by(mini_category='Otherkitchenware').all()

	miniwoofers=Product.query.filter_by(mini_category='Woofers').all()
	minifridges=Product.query.filter_by(mini_category='Fridges').all()
	miniphones=Product.query.filter_by(mini_category='Phones').all()
	otherelectronics=Product.query.filter_by(mini_category='Otherelectronics').all()

	minibedsheets=Product.query.filter_by(mini_category='Bedsheets').all()
	miniduvets=Product.query.filter_by(mini_category='Duvets').all()
	mininets=Product.query.filter_by(mini_category='Mosquito Nets').all()
	minipillows=Product.query.filter_by(mini_category='Pillows').all()

	#minimenshoes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomenshoes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrenshoes=Product.query.filter_by(mini_category='Childrens').all()
	#othershoes=Product.query.filter_by(mini_category='Others').all()

	#minimensclothes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomensclothes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrensclothes=Product.query.filter_by(mini_category='Childrens').all()
	#otherclothes=Product.query.filter_by(mini_category='Others').all()

	minichairs=Product.query.filter_by(mini_category='Chairs').all()
	miniracks=Product.query.filter_by(mini_category='Shoe Racks').all()
	miniwardrobes=Product.query.filter_by(mini_category='Wardrobes').all()
	otherfurniture=Product.query.filter_by(mini_category='Otherfurniture').all()

	generals=Product.query.filter_by(product_category='General').all()

	deal=Deal.query.all()

	return render_template('index.html', form=form,deal=deal,
		generals=generals, minichairs=minichairs, miniracks=miniracks,miniwardrobes=miniwardrobes,otherfurniture=otherfurniture,
	    minibedsheets=minibedsheets,miniduvets=miniduvets,mininets=mininets,minipillows=minipillows,
		miniwoofers=miniwoofers,minifridges=minifridges,miniphones=miniphones,otherelectronics=otherelectronics,
		minipans=minipans,minicutlery=minicutlery,minikitchenelectronics=minikitchenelectronics,otherkitchenware=otherkitchenware)



@app.route('/signin', methods=['POST', 'GET'])
def signin():
	form = SigninForm()
	if form.validate_on_submit():
		user=User.query.filter_by(username=form.username.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, remember=True)

			if current_user.username=='Administrator' or 'mhtani' or 'hillary' or 'mungai38':
				flash('You are now logged in Admin')
				return redirect(request.args.get('next') or url_for('backoffice'))
			else:
				flash('Permission denied! sorry you cant login')
			return redirect(url_for('index'))
		else:
			flash('The username or password is wrong please enter correct credentials')
			return redirect(url_for('signin'))
			
	return render_template('signin.html', form=form)


@app.route('/backoffice')
@login_required
def backoffice():

	minipans=Product.query.filter_by(mini_category='Pans').all()
	minicutlery=Product.query.filter_by(mini_category='Cutlery').all()
	minikitchenelectronics=Product.query.filter_by(mini_category='Kitchen Electronics').all()
	otherkitchenware=Product.query.filter_by(mini_category='Otherkitchenware').all()

	miniwoofers=Product.query.filter_by(mini_category='Woofers').all()
	minifridges=Product.query.filter_by(mini_category='Fridges').all()
	miniphones=Product.query.filter_by(mini_category='Phones').all()
	otherelectronics=Product.query.filter_by(mini_category='Otherelectronics').all()

	minibedsheets=Product.query.filter_by(mini_category='Bedsheets').all()
	miniduvets=Product.query.filter_by(mini_category='Duvets').all()
	mininets=Product.query.filter_by(mini_category='Mosquito Nets').all()
	minipillows=Product.query.filter_by(mini_category='Pillows').all()

	#minimenshoes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomenshoes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrenshoes=Product.query.filter_by(mini_category='Childrens').all()
	#othershoes=Product.query.filter_by(mini_category='Others').all()

	#minimensclothes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomensclothes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrensclothes=Product.query.filter_by(mini_category='Childrens').all()
	#otherclothes=Product.query.filter_by(mini_category='Others').all()

	minichairs=Product.query.filter_by(mini_category='Chairs').all()
	miniracks=Product.query.filter_by(mini_category='Shoe Racks').all()
	miniwardrobes=Product.query.filter_by(mini_category='Wardrobes').all()
	otherfurniture=Product.query.filter_by(mini_category='Otherfurniture').all()

	generals=Product.query.filter_by(product_category='General').all()

	return render_template('backoffice.html',
		generals=generals, minichairs=minichairs, miniracks=miniracks,miniwardrobes=miniwardrobes,otherfurniture=otherfurniture,
		minibedsheets=minibedsheets,miniduvets=miniduvets,mininets=mininets,minipillows=minipillows,
		miniwoofers=miniwoofers,minifridges=minifridges,miniphones=miniphones,otherelectronics=otherelectronics,
		minipans=minipans,minicutlery=minicutlery,minikitchenelectronics=minikitchenelectronics,otherkitchenware=otherkitchenware)



#New signup with confirmation
def send_confirmation_email(user_email):
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
 
    confirm_url = url_for(
        'confirm_email',
        token=confirm_serializer.dumps(user_email, salt='email-confirmation-salt'),
        _external=True)
 
    #html = render_template(
        #'email_confirmation.html',
        #confirm_url=confirm_url)
 
    #send_email('Confirm Your Email Address', [user_email], [html])



    send_email('Confirm Your Email Address',
		[user_email],
		confirm_url,
		render_template('email_confirmation.html',confirm_url=confirm_url))



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                filename=images.save(request.files['attach_photo'])
                url=images.url(filename)

                user =User(surname=form.surname.data,
			        othernames=form.othernames.data,
			        admin=form.admin.data,
			        attach_photo=url,
			        city=form.city.data,
			        residence=form.residence.data,
			        mobile_number=form.mobile_number.data,
			        telephone_number=form.telephone_number.data,
			        email=form.email.data,
			        username=form.username.data,
			        password_hash=generate_password_hash(form.password.data))
                db.session.add(user)
                db.session.commit()

 
                send_confirmation_email(user.email)
                flash('Thanks for registering with Us!  Please check your email to confirm your email address.', 'All the best')
                return redirect(url_for('index'))

            except ValidationError:
                db.session.rollback()
                flash('ERROR! Email ({}) already exists.'.format(form.email.data), 'error')
    return render_template('signup.html', form=form)



#confirming the token
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt='email-confirmation-salt', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'error')
        return redirect(url_for('signin'))
 
    user = User.query.filter_by(email=email).first()
 
    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'info')
    else:
        user.email_confirmed = True
        user.email_confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Thank you for confirming your email address! All the best')
 
    return redirect(url_for('index'))




#Edit profile
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
	form=ProfileForm()
	if form.validate_on_submit():
		current_user.surname=form.surname.data
		current_user.othernames=form.othernames.data

		filename=images.save(request.files['attach_photo'])
		url=images.url(filename)

		current_user.attach_photo=url
		current_user.mobile_number=form.mobile_number.data
		current_user.telephone_number=form.telephone_number.data
		current_user.email=form.email.data
		current_user.city=form.city.data
		current_user.residence=form.residence.data

		db.session.add(current_user._get_current_object())
		db.session.commit()

		flash('Your Profile has been Updated')

		return redirect(url_for('backoffice', username=current_user.username))
		
	return render_template('profile.html', form=form)


@app.route('/edititem/<int:id>', methods=['GET','POST'])
@login_required
def edit(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=EdititemForm()
	if form.validate_on_submit():
		front_image=images.save(request.files['front_image'])
		front_url=images.url(front_image)


		item.product_name=form.product_name.data
		item.product_description=form.product_description.data
		item.real_price=form.real_price.data
		item.first_price=form.first_price.data
		item.front_image=front_url

		#db.session.add(item._get_current_object())	
		db.session.commit()

		flash('The item has been successfuly updated')
		return redirect(url_for('backoffice',user=current_user))
		
	return render_template('edititem.html',item=item, form=form)



@app.route('/deleteitem/<int:id>')
@login_required
def deleteitem(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	db.session.delete(item)
	db.session.commit()

	flash('The item has been deleted')
	return redirect(url_for('backoffice', user=current_user))
	

@app.route('/addsideimage/<int:id>', methods=['GET','POST'])
@login_required
def addsideimage(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=SideimageForm()
	if form.validate_on_submit():
		image2=images.save(request.files['side_image'])
		side_url=images.url(image2)

		item.side_image=side_url
		db.session.commit()

		flash('The side inage has been successfuly added')
		return redirect(url_for('backoffice', user=current_user))
		
	return render_template('sideimage.html',item=item, form=form)


@app.route('/addhindimage/<int:id>', methods=['GET','POST'])
@login_required
def addhindimage(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=HindimageForm()
	if form.validate_on_submit():
		image3=images.save(request.files['hind_image'])
		hind_url=images.url(image3)

		item.hind_image=hind_url
		db.session.commit()

		flash('The backside image has been successfuly added')
		return redirect(url_for('backoffice', user=current_user))
		
	return render_template('hindimage.html',item=item, form=form)


@app.route('/additem1/<int:id>', methods=['GET','POST'])
@login_required
def additem1(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=BonusitemForm()
	if form.validate_on_submit():
		alsobought1=images.save(request.files['alsobought_image'])
		alsobought_url=images.url(alsobought1)

		item.alsobought1=form.alsobought.data
		item.alsoboughtimage1=alsobought_url
		item.alsobought_description1=form.alsobought_description.data
		item.alsoboughtreal_price1=form.alsoboughtreal_price.data
		item.alsoboughtfirst_price1=form.alsoboughtfirst_price.data

		db.session.commit()

		flash('The bundle item has been successfuly added')
		return redirect(url_for('backoffice', user=current_user))
		
	return render_template('alsobought1.html',item=item, form=form)

@app.route('/additem2/<int:id>', methods=['GET','POST'])
@login_required
def additem2(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=BonusitemForm()
	if form.validate_on_submit():
		alsobought2=images.save(request.files['alsobought_image'])
		alsobought_url=images.url(alsobought2)

		item.alsobought2=form.alsobought.data
		item.alsobought_description2=form.alsobought_description.data
		item.alsoboughtimage2=alsobought_url
		item.alsoboughtreal_price2=form.alsoboughtreal_price.data
		item.alsoboughtfirst_price2=form.alsoboughtfirst_price.data

		db.session.commit()

		flash('The bundle item has been successfuly added')
		return redirect(url_for('backoffice', user=current_user))
		
	return render_template('alsobought2.html',item=item, form=form)

@app.route('/additem3/<int:id>', methods=['GET','POST'])
@login_required
def additem3(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=BonusitemForm()
	if form.validate_on_submit():
		alsobought3=images.save(request.files['alsobought_image'])
		alsobought_url=images.url(alsobought3)

		item.alsobought3=form.alsobought.data
		item.alsobought_description3=form.alsobought_description.data
		item.alsoboughtimage3=alsobought_url
		item.alsoboughtreal_price3=form.alsoboughtreal_price.data
		item.alsoboughtfirst_price3=form.alsoboughtfirst_price.data

		db.session.commit()

		flash('The bundle item has been successfuly added')
		return redirect(url_for('backoffice', user=current_user))
		
	return render_template('alsobought3.html',item=item, form=form)

@app.route('/additem4/<int:id>', methods=['GET','POST'])
@login_required
def additem4(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	form=BonusitemForm()
	if form.validate_on_submit():
		alsobought4=images.save(request.files['alsobought_image'])
		alsobought_url=images.url(alsobought4)

		item.alsobought4=form.alsobought.data
		item.alsobought_description4=form.alsobought_description.data
		item.alsoboughtimage4=alsobought_url
		item.alsoboughtreal_price4=form.alsoboughtreal_price.data
		item.alsoboughtfirst_price4=form.alsoboughtfirst_price.data

		db.session.commit()

		flash('The bundle item has been successfuly added')
		return redirect(url_for('backoffice', user=current_user))
		
	return render_template('alsobought4.html',item=item, form=form)


@app.route('/addbundleitem/<int:id>')
@login_required
def addbundleitem(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	return render_template('bundleitem.html', item=item)


@app.route('/shop')
def shop():
	return render_template('shop.html')

#product views
@app.route('/electronics', methods=['POST','GET'])
def electronics():
	form=ElectronicsForm()
	if form.validate_on_submit():
		image1=images.save(request.files['front_image'])
		front_url=images.url(image1)

		electronic = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      mini_category=form.mini_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
		db.session.add(electronic)
		db.session.commit()

		flash('Item has been succesfully posted')
		return redirect(url_for('backoffice', username=current_user.username))
	return render_template('electronics.html', form=form)


@app.route('/beddings', methods=['POST','GET'])
def beddings():
	form=BeddingsForm()
	if form.validate_on_submit():
	    image1=images.save(request.files['front_image'])
	    front_url=images.url(image1)


	    bedding = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      mini_category=form.mini_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
	    db.session.add(bedding)
	    db.session.commit()

	    flash('Item has been succesfully posted')

	    return redirect(url_for('backoffice', username=current_user.username))

	return render_template('beddings.html', form=form)


@app.route('/kitchenware', methods=['POST','GET'])
def kitchenware():
	form=KitchenwareForm()
	if form.validate_on_submit():
	    image1=images.save(request.files['front_image'])
	    front_url=images.url(image1)

	    kitchenware = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      mini_category=form.mini_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
	    db.session.add(kitchenware)
	    db.session.commit()

	    flash('Item has been succesfully posted')

	    return redirect(url_for('backoffice', username=current_user.username))

	return render_template('kitchenware.html', form=form)



@app.route('/shoes', methods=['POST','GET'])
def shoes():
	form=ShoesForm()
	if form.validate_on_submit():
	    image1=images.save(request.files['front_image'])
	    front_url=images.url(image1)

	    shoe = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      mini_category=form.mini_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
	    db.session.add(shoe)
	    db.session.commit()

	    flash('Item has been succesfully posted')

	    return redirect(url_for('backoffice', username=current_user.username))

	return render_template('shoes.html', form=form)



@app.route('/clothes', methods=['POST','GET'])
def clothes():
	form=ClothesForm()
	if form.validate_on_submit():
	    image1=images.save(request.files['front_image'])
	    front_url=images.url(image1)

	   
	    clothe = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      mini_category=form.mini_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
	    db.session.add(clothe)
	    db.session.commit()

	    flash('Item has been succesfully posted')

	    return redirect(url_for('backoffice', username=current_user.username))

	return render_template('clothes.html', form=form)



@app.route('/furniture', methods=['POST','GET'])
def furniture():
	form=FurnitureForm()
	if form.validate_on_submit():
	    image1=images.save(request.files['front_image'])
	    front_url=images.url(image1)

	    furniture = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      mini_category=form.mini_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
	    db.session.add(furniture)
	    db.session.commit()

	    flash('Item has been succesfully posted')

	    return redirect(url_for('backoffice', username=current_user.username))

	return render_template('furniture.html', form=form)


@app.route('/general', methods=['POST','GET'])
def general():
	form=GeneralForm()
	if form.validate_on_submit():
	    image1=images.save(request.files['front_image'])
	    front_url=images.url(image1)

	    general = Product(
			      user_id=form.agent_id.data,
			      product_category=form.product_category.data,
			      product_name=form.product_name.data,
			      product_description=form.product_description.data,
			      front_image=front_url,
			      real_price=form.real_price.data,
			      first_price=form.first_price.data,
			      user = current_user)
	    db.session.add(general)
	    db.session.commit()

	    flash('Item has been succesfully posted')

	    return redirect(url_for('backoffice', username=current_user.username))

	return render_template('general.html', form=form)




@app.route('/minikitchenware')
def minikitchenware():
	minipans=Product.query.filter_by(mini_category='Pans').all()
	minicutlery=Product.query.filter_by(mini_category='Cutlery').all()
	minikitchenelectronics=Product.query.filter_by(mini_category='Kitchen Electronics').all()
	otherkitchenware=Product.query.filter_by(mini_category='Otherkitchenware').all()
	

	return render_template('minikitchenware.html', minipans=minipans, minicutlery=minicutlery,
		minikitchenelectronics=minikitchenelectronics, otherkitchenware=otherkitchenware)


@app.route('/mainpans/<name>', methods=['GET','POST'])
def mainpans(name):
	minipan=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainpans.html', minipan=minipan, name=name)


@app.route('/maincutlery/<name>', methods=['GET','POST'])
def maincutlery(name):
	minicutlery=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('maincutlery.html', minicutlery=minicutlery, name=name)


@app.route('/mainkitchenelectronics/<name>', methods=['GET','POST'])
def mainkitchenelectronics(name):
	minielectronic=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainkitchenelectronics.html', minielectronic=minielectronic, name=name)


@app.route('/otherkitchenware/<name>', methods=['GET','POST'])
def otherkitchenware(name):
	miniother=Product.query.filter_by(product_name=name).first_or_404()

	return render_template('otherkitchenware.html', miniother=miniother, name=name)





@app.route('/minielectronics')
def minielectronics():
	miniwoofers=Product.query.filter_by(mini_category='Woofers').all()
	minifridges=Product.query.filter_by(mini_category='Fridges').all()
	miniphones=Product.query.filter_by(mini_category='Phones').all()
	otherelectronics=Product.query.filter_by(mini_category='Otherelectronics').all()

	return render_template('minielectronics.html', miniwoofers=miniwoofers, minifridges=minifridges,
		miniphones=miniphones, otherelectronics=otherelectronics)


@app.route('/mainwoofers/<name>', methods=['GET','POST'])
def mainwoofers(name):
	miniwoofer=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainwoofers.html', miniwoofer=miniwoofer, name=name)


@app.route('/mainfridges/<name>', methods=['GET','POST'])
def mainfridges(name):
	minifridge=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainfridges.html', minifridge=minifridge, name=name)


@app.route('/mainphones/<name>', methods=['GET','POST'])
def mainphones(name):
	miniphone=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainphones.html', miniphone=miniphone, name=name)



@app.route('/otherelectronics/<name>', methods=['GET','POST'])
def otherelectronics(name):
	other=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('otherelectronics.html', other=other, name=name)


@app.route('/minibeddings')
def minibeddings():
	minibedsheets=Product.query.filter_by(mini_category='Bedsheets').all()
	miniduvets=Product.query.filter_by(mini_category='Duvets').all()
	mininets=Product.query.filter_by(mini_category='Mosquito Nets').all()
	minipillows=Product.query.filter_by(mini_category='Pillows').all()

	return render_template('minibeddings.html', minibedsheets=minibedsheets, miniduvets=miniduvets,
		mininets=mininets, minipillows=minipillows)


@app.route('/mainbedsheets/<name>', methods=['GET','POST'])
def mainbedsheets(name):
	minibedsheet=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainbedsheets.html', minibedsheet=minibedsheet, name=name)


@app.route('/mainduvets/<name>', methods=['GET','POST'])
def mainduvets(name):
	miniduvet=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainduvets.html', miniduvet=miniduvet, name=name)


@app.route('/mainnets/<name>', methods=['GET','POST'])
def mainnets(name):
	mininet=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainnets.html', mininet=mininet, name=name)



@app.route('/mainpillows/<name>', methods=['GET','POST'])
def mainpillows(name):
	minipillow=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainpillows.html', minipillow=minipillow, name=name)






@app.route('/minishoes')
def minishoes():
	minimenshoes=Product.query.filter_by(mini_category='Mens').all()
	miniwomenshoes=Product.query.filter_by(mini_category='Womens').all()
	minichildrenshoes=Product.query.filter_by(mini_category='Childrens').all()
	othershoes=Product.query.filter_by(mini_category='Othershoes').all()

	return render_template('minishoes.html', minimenshoes=minimenshoes, miniwomenshoes=miniwomenshoes,
		minichildrenshoes=minichildrenshoes, othershoes=othershoes)


@app.route('/menshoes/<name>', methods=['GET','POST'])
def menshoes(name):
	minimenshoes=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('menshoes.html', minimenshoes=minimenshoes, name=name)



@app.route('/womenshoes/<name>', methods=['GET','POST'])
def womenshoes(name):
	miniwomenshoes=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('womenshoes.html', miniwomenshoes=miniwomenshoes, name=name)


@app.route('/childrenshoes/<name>', methods=['GET','POST'])
def childrenshoes(name):
	childshoes=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('childrenshoes.html', childshoes=childshoes, name=name)




@app.route('/othershoes/<name>', methods=['GET','POST'])
def othershoes(name):
	other=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('othershoes.html', other=other, name=name)




@app.route('/miniclothes')
def miniclothes():
	minimensclothes=Product.query.filter_by(mini_category='Mens').all()
	miniwomensclothes=Product.query.filter_by(mini_category='Womens').all()
	minichildrensclothes=Product.query.filter_by(mini_category='Childrens').all()
	otherclothes=Product.query.filter_by(mini_category='Otherclothes').all()

	return render_template('miniclothes.html', minimensclothes=minimensclothes, miniwomensclothes=miniwomensclothes,
		minichildrensclothes=minichildrensclothes, otherclothes=otherclothes)

@app.route('/mensclothes/<name>', methods=['GET','POST'])
def mensclothes(name):
	minimensclothes=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mensclothes.html', minimensclothes=minimensclothes, name=name)


@app.route('/womensclothes/<name>', methods=['GET','POST'])
def womensclothes(name):
	miniwomensclothes=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('womensclothes.html', miniwomensclothes=miniwomensclothes, name=name)



@app.route('/childrensclothes/<name>', methods=['GET','POST'])
def childrensclothes(name):
	childsclothes=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('childrensclothes.html', childsclothes=childsclothes, name=name)



@app.route('/otherclothes/<name>', methods=['GET','POST'])
def otherclothes(name):
	other=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('otherclothes.html', other=other, name=name)





@app.route('/minifurniture')
def minifurniture():
	minichairs=Product.query.filter_by(mini_category='Chairs').all()
	miniracks=Product.query.filter_by(mini_category='Shoe Racks').all()
	miniwardrobes=Product.query.filter_by(mini_category='Wardrobes').all()
	otherfurniture=Product.query.filter_by(mini_category='Otherfurniture').all()

	return render_template('minifurniture.html', minichairs=minichairs, miniracks=miniracks,
		miniwardrobes=miniwardrobes, otherfurniture=otherfurniture)


@app.route('/mainchairs/<name>', methods=['GET','POST'])
def mainchairs(name):
	minichair=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainchairs.html', minichair=minichair, name=name)


@app.route('/mairacks/<name>', methods=['GET','POST'])
def mainracks(name):
	minirack=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainracks.html', minirack=minirack, name=name)



@app.route('/mainwardrobes/<name>', methods=['GET','POST'])
def mainwardrobes(name):
	miniwardrobe=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('mainwardrobes.html', miniwardrobe=miniwardrobe, name=name)


@app.route('/otherfurniture/<name>', methods=['GET','POST'])
def otherfurniture(name):
	other=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('otherfurniture.html',other=other, name=name)





@app.route('/minigeneral')
def minigeneral():
	generals=Product.query.filter_by(product_category='General').all()
	return render_template('minigeneral.html', generals=generals)


@app.route('/maingeneral/<name>', methods=['GET','POST'])
def maingeneral(name):
	general=Product.query.filter_by(product_name=name).first_or_404()
	return render_template('maingeneral.html', general=general, name=name)





@app.route('/productdetails')
def productdetails():
	return render_template('productdetails.html')


	
@app.route('/bundle1/<int:id>')
def bundle1(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	return render_template('bundle1.html', item=item)

@app.route('/bundle2/<int:id>')
def bundle2(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	return render_template('bundle2.html', item=item)

@app.route('/bundle3/<int:id>')
def bundle3(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	return render_template('bundle3.html', item=item)

@app.route('/bundle4/<int:id>')
def bundle4(id):
	item=Product.query.filter_by(product_id=id).first_or_404()
	return render_template('bundle4.html', item=item)



@app.route('/optionone', methods=['GET','POST'])
def optionone():
	form=OrderForm()
	if form.validate_on_submit():
		productname=form.productname.data
		color=form.color.data
		size=form.size.data
		quantity=form.quantity.data
		clientemail=form.email.data
		clientname=form.clientname.data
		mobile_number=form.mobile_number.data
		address=form.address.data
		recipient_email='onlinehomeshoppingug@gmail.com'
		send_email('Orders',
		[recipient_email],
		address,
		render_template('emailorder.html', productname=productname,color=color,size=size,
			quantity=quantity,clientname=clientname,clientemail=clientemail, mobile_number=mobile_number, address=address))

		order=Order(
			product_name=form.productname.data,
			color=form.color.data,
			quantity=form.quantity.data,
			size=form.size.data,
			client_name=form.clientname.data,
			mobile_number=form.mobile_number.data,
			email=form.email.data,
			address=form.address.data)
		db.session.add(order)
		db.session.commit()

		flash('Your order has been Received, delivery Underway')
		return redirect(url_for('index'))
		
	return render_template('optionone.html', form=form)


@app.route('/optiontwo')
def optiontwo():
	return render_template('optiontwo.html')


@app.route('/customercaredesk', methods=['GET','POST'])
def customercaredesk():
	form=CommentForm()
	if form.validate_on_submit():
		clientname=form.name.data
		clientemail=form.email.data
		mobile=form.mobile_number.data
		clientconcern=form.concern.data
		recipient_email='onlinehomeshoppingug@gmail.com'

		send_email('Feedback',
		[recipient_email],
		clientconcern,
		render_template('feedback.html',clientname=clientname,clientemail=clientemail,mobile=mobile,
			clientconcern=clientconcern))

		flash('Thank you for your feedback, we shall respond in kind')
		return redirect(url_for('index'))
		
	return render_template('customercaredesk.html',form=form)

@app.route('/checkout')
def checkout():
	return render_template('checkout.html')

@app.route('/order')
def order():
	form=OrderForm()
	if form.validate_on_submit():
		pass
	return render_template('order.html', form=form)


@app.route('/base')
def base():
	return render_template('base.html')


@app.route('/postproduct')
def postproduct():
	form=PostproductForm()
	if form.validate_on_submit():
		pass
	return render_template('postproduct.html', form=form)


@app.route('/contactseller')
def contactseller():
	form=ContactForm()
	if form.validate_on_submit():
		pass
	return render_template('contactseller.html', form=form)

@app.route('/contact')
def contact():
	return render_template('contact.html')


@app.route('/single', methods=['GET','POST'])
def single():
	form=OrderForm()
	if form.validate_on_submit():
		pass
	return render_template('single.html', form=form)

@app.route('/newstock')
def newstock():
	minipans=Product.query.filter_by(mini_category='Pans').all()
	minicutlery=Product.query.filter_by(mini_category='Cutlery').all()
	minikitchenelectronics=Product.query.filter_by(mini_category='Kitchen Electronics').all()
	otherkitchenware=Product.query.filter_by(mini_category='Otherkitchenware').all()

	miniwoofers=Product.query.filter_by(mini_category='Woofers').all()
	minifridges=Product.query.filter_by(mini_category='Fridges').all()
	miniphones=Product.query.filter_by(mini_category='Phones').all()
	otherelectronics=Product.query.filter_by(mini_category='Otherelectronics').all()

	minibedsheets=Product.query.filter_by(mini_category='Bedsheets').all()
	miniduvets=Product.query.filter_by(mini_category='Duvets').all()
	mininets=Product.query.filter_by(mini_category='Mosquito Nets').all()
	minipillows=Product.query.filter_by(mini_category='Pillows').all()

	#minimenshoes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomenshoes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrenshoes=Product.query.filter_by(mini_category='childrenshoes').all()
	#othershoes=Product.query.filter_by(mini_category='Others').all()

	#minimensclothes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomensclothes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrensclothes=Product.query.filter_by(mini_category='childrensclothes').all()
	#otherclothes=Product.query.filter_by(mini_category='Others').all()

	minichairs=Product.query.filter_by(mini_category='Chairs').all()
	miniracks=Product.query.filter_by(mini_category='Shoe Racks').all()
	miniwardrobes=Product.query.filter_by(mini_category='Wardrobes').all()
	otherfurniture=Product.query.filter_by(mini_category='Otherfurniture').all()

	generals=Product.query.filter_by(product_category='General').all()

	return render_template('newstock.html',
		generals=generals, minichairs=minichairs, miniracks=miniracks,miniwardrobes=miniwardrobes,otherfurniture=otherfurniture,
		minibedsheets=minibedsheets,miniduvets=miniduvets,mininets=mininets,minipillows=minipillows,
		miniwoofers=miniwoofers,minifridges=minifridges,miniphones=miniphones,otherelectronics=otherelectronics,
		minipans=minipans,minicutlery=minicutlery,minikitchenelectronics=minikitchenelectronics,otherkitchenware=otherkitchenware)

@app.route('/generalsearch',methods=['GET','POST'])
def generalsearch():
	form=GeneralsearchForm()
	if form.validate_on_submit():
		search=form.search.data
		return redirect(url_for('search'))
	minipans=Product.query.filter_by(mini_category='Pans').all()
	minicutlery=Product.query.filter_by(mini_category='Cutlery').all()
	minikitchenelectronics=Product.query.filter_by(mini_category='Kitchen Electronics').all()
	otherkitchenware=Product.query.filter_by(mini_category='Otherkitchenware').all()

	miniwoofers=Product.query.filter_by(mini_category='Woofers').all()
	minifridges=Product.query.filter_by(mini_category='Fridges').all()
	miniphones=Product.query.filter_by(mini_category='Phones').all()
	otherelectronics=Product.query.filter_by(mini_category='Otherelectronics').all()

	minibedsheets=Product.query.filter_by(mini_category='Bedsheets').all()
	miniduvets=Product.query.filter_by(mini_category='Duvets').all()
	mininets=Product.query.filter_by(mini_category='Mosquito Nets').all()
	minipillows=Product.query.filter_by(mini_category='Pillows').all()

	#minimenshoes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomenshoes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrenshoes=Product.query.filter_by(mini_category='Childrens').all()
	#othershoes=Product.query.filter_by(mini_category='Others').all()

	#minimensclothes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomensclothes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrensclothes=Product.query.filter_by(mini_category='Childrens').all()
	#otherclothes=Product.query.filter_by(mini_category='Others').all()

	minichairs=Product.query.filter_by(mini_category='Chairs').all()
	miniracks=Product.query.filter_by(mini_category='Shoe Racks').all()
	miniwardrobes=Product.query.filter_by(mini_category='Wardrobes').all()
	otherfurniture=Product.query.filter_by(mini_category='Otherfurniture').all()

	generals=Product.query.filter_by(product_category='General').all()

	return render_template('index.html', form=form,
		generals=generals, minichairs=minichairs, miniracks=miniracks,miniwardrobes=miniwardrobes,otherfurniture=otherfurniture,
	    minibedsheets=minibedsheets,miniduvets=miniduvets,mininets=mininets,minipillows=minipillows,
		miniwoofers=miniwoofers,minifridges=minifridges,miniphones=miniphones,otherelectronics=otherelectronics,
		minipans=minipans,minicutlery=minicutlery,minikitchenelectronics=minikitchenelectronics,otherkitchenware=otherkitchenware)


@app.route('/search', methods=['GET','POST'])
def search():
	minipans=Product.query.filter_by(mini_category='Pans').all()
	minicutlery=Product.query.filter_by(mini_category='Cutlery').all()
	minikitchenelectronics=Product.query.filter_by(mini_category='Kitchen Electronics').all()
	otherkitchenware=Product.query.filter_by(mini_category='Otherkitchenware').all()

	miniwoofers=Product.query.filter_by(mini_category='Woofers').all()
	minifridges=Product.query.filter_by(mini_category='Fridges').all()
	miniphones=Product.query.filter_by(mini_category='Phones').all()
	otherelectronics=Product.query.filter_by(mini_category='Otherelectronics').all()

	minibedsheets=Product.query.filter_by(mini_category='Bedsheets').all()
	miniduvets=Product.query.filter_by(mini_category='Duvets').all()
	mininets=Product.query.filter_by(mini_category='Mosquito Nets').all()
	minipillows=Product.query.filter_by(mini_category='Pillows').all()

	#minimenshoes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomenshoes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrenshoes=Product.query.filter_by(mini_category='Childrens').all()
	#othershoes=Product.query.filter_by(mini_category='Others').all()

	#minimensclothes=Product.query.filter_by(mini_category='Mens').all()
	#miniwomensclothes=Product.query.filter_by(mini_category='Womens').all()
	#minichildrensclothes=Product.query.filter_by(mini_category='Childrens').all()
	#otherclothes=Product.query.filter_by(mini_category='Others').all()

	minichairs=Product.query.filter_by(mini_category='Chairs').all()
	miniracks=Product.query.filter_by(mini_category='Shoe Racks').all()
	miniwardrobes=Product.query.filter_by(mini_category='Wardrobes').all()
	otherfurniture=Product.query.filter_by(mini_category='Otherfurniture').all()

	generals=Product.query.filter_by(product_category='General').all()

	return render_template('searchresults.html',
		generals=generals, minichairs=minichairs, miniracks=miniracks,miniwardrobes=miniwardrobes,otherfurniture=otherfurniture,
	    minibedsheets=minibedsheets,miniduvets=miniduvets,mininets=mininets,minipillows=minipillows,
		miniwoofers=miniwoofers,minifridges=minifridges,miniphones=miniphones,otherelectronics=otherelectronics,
		minipans=minipans,minicutlery=minicutlery,minikitchenelectronics=minikitchenelectronics,otherkitchenware=otherkitchenware)


@app.route('/deals', methods=['GET','POST'])
def deals():
	form=DealForm()
	if form.validate_on_submit():
		deal=images.save(request.files['deal_image'])
		deal_url=images.url(deal)
		deal=Deal(
			user_id=form.agent_id.data,
			title=form.title.data,
			deal_description=form.deal_description.data,
			deal_image=deal_url)
		db.session.add(deal)
		db.session.commit()

		flash('The deal has been posted')
		return redirect(url_for('backoffice', user=current_user))
	return render_template('deal.html', form=form)




@app.route('/about')
def about():
	return render_template('about.html')

@app.route('/signout')
@login_required
def signout():
	logout_user()
	flash('You have been logged out. Signin to Access the Backoffice')
	return redirect(url_for('index'))


@app.errorhandler(404)
def error(e):
	return render_template('error.html')






if __name__=="__main__":
	app.run(host='localhost', port=3030, debug=True)
