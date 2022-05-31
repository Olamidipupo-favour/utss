from flask import Flask,session,render_template,jsonify,flash,request,make_response
import flask_wtf
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail,Message
from flask_cors import CORS
from werkzeug.security import generate_password_hash,check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
from datetime import datetime
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite://test.db'
app.config['MAIL_SERVER']='smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'blah'
app.config['MAIL_PASSWORD'] = 'cfaf5b99f8bafb'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['SECRET_KEY']:'Development shit'

cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
MAX_TRIES=20
UPLOAD='tmp/uploads'
#maximum possible login tries
#checking of sessions expire
db=SQLAlchemy(app)
mail=Mail(app)
def validate(*args):
	for i in args:
		if len(i)<5 :
			return False
	return True
class Users(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	first_name=db.Column(db.String(100))
	last_name=db.Column(db.String(100))
	email=db.Column(db.String(100),unique=True)
	password=db.Column(db.String(120))
	admin=db.Column(db.Boolean)
	student=db.Column(db.Boolean)
	teacher=db.Column(db.Boolean)
	dp=db.Column(db.String(300),unique=True)
	def __init__(first_name,last_name,email,password,admin=False,student=True,teacher=False,dp='default.png'):
		self.first_name=first_name
		self.last_name=last_name
		self.email=email
		self.password=password
		self.admin=admin
		self.student=student
		self.teacher=teacher
		self.dp=dp
class Visitor(db.Model):
		id=db.Column(db.Integer,primary_key=True)
		ip=db.Column(db.String(100),unique=True)
		date=db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
		def __init__(self,ip,date=datetime.utcnow):
			self.ip=ip
			self.date=date
class Subject(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	name=db.Column(db.String(100),unique=True)
	teacher=db.Column(db.Integer)
	def __init__(self,name,teacher):
		self.name=name
		self.teacher=teacher
		#teacher should be the id of the teacher involved.
class Notification(db.Model):
	id=db.Column(db.Integer,primary_key=True)
	date=db.Column(db.DateTime,default=datetime.utcnow)
	name=db.Column(db.Text)
	def __init__(self,name,date=datetime.utcnow):
		self.name=name
		self.date=date
class Suscriber(db.Model):
		id=db.Column(db.Integer,primary_key=True)
		email=db.Column(db.String(100),unique=True)
		name=db.Column(db.String(100))
		def __init__(self,email,name):
			self.first_name=first_name
			self.last_name=last_name
			self.email=email		
@app.route('/api/login',methods=['POST'])
def login():
	uid=request.form.get('uid')
	password=request.form.get('password')
	if(session['attempts']>MAX_TRIES):
		return jsonify({'error':'max_retries_exceeded'})
	if(validate(uid,password)):
		user_data=Users.query.filter_by(email=uid).first()
		if(check_password_hash(password,user_data.password)):
			res={
			'first_name':user_data.first_name,
			'last_name':user_data.last_name,
			'email':user_data.email,
			'is_admin':user_data.admin,
			'is_student':user_data.student,
			'is_teacher':user_data.teacher,
			'dp':user_data.dp
			}
			role={
				'is_admin':user_data.admin,
			'is_student':user_data.student,
			'is_teacher':user_data.teacher,
			}
			session['logged_in']=True
			session['role']=role
			session['admin']=user_data.admin
			session['uid']=user_data.id
			session['attempts']=0
			resp=make_response(jsonify(res))
			resp.set_cookie('uid',user_data.id)
			resp.set_cookie('role',role)
			return resp
		else:
			try:
				session['attempts']+=1
			except:
				session['attempts']=1
			return jsonify({'error':'wrong_password/username_combination'})
	else:
		jsonify({'error':'validation_error'})
@app.route('/api/logout',methods=['POST'])
def logout():
	del session['logged_in']
	del session['role']
	del session['uid']
	del session['admin']
	res={'message':'logged_out'}
	resp=make_response(jsonify(res))
	resp.set_cookie('uid',None)
	resp.set_cookie('role',None)
	return resp
@app.route('/api/register',methods=['POST'])
def register():
	##To be accessed by admin only.
	uid=session.get('uid')
	is_admin=session.get('admin')
	if(is_admin):
		if(request.form.get('xls')):
			#add users from a spreadsheet.
			f=request.files['xls_file']
			if(f):
				f.save(UPLOAD,secure_filename(f.filename))
				workbook=pd.read_excel(UPLOAD+'/'+secure_filename(f.filename))
				for i in range(0,len(workbook['first_name'].iloc)):
					first_name=workbook['first_name'].iloc[str(i)]
					last_name=workbook['last_name'].iloc[str(i)]
					email=workbook['email'].iloc[str(i)]
					password=generate_password_hash(workbook['password'].iloc[str(i)])
					admin=workbook['first_name'].iloc[str(i)]
					student=workbook['first_name'].iloc[str(i)]
					teacher=workbook['first_name'].iloc[str(i)]
			user=User(first_name,last_name,email,password,admin,student,teacher)
			db.session.add(user)
			db.session.commit()
			#when possible,put the statement above in a try-catch.
			return jsonify({'message':'Users_successfully_created'})	
		else:
			first_name=request.form.get('first_name')
			last_name=request.form.get('last_name')
			email=request.form.get('email')
			student=request.form.get('student')
			teacher=request.form.get('teacher')	
			admin=request.form.get('admin')			
			password=generate_password_hash(request.form.get('password'))
			user=User(first_name,last_name,email,password,admin,student,teacher)
			db.session.add(user)
			db.session.commit()
			#when possible,put the statement above in a try-catch.
			return jsonify({'message':'User_successfully_created'})
	else:
		return jsonify({'message':'Unauthorized'}),304
@app.route('/api/visitor/add',methods=['POST'])
def add_visitors():
	ip=request.remote_addr
	if(session['visited']):
		v=Visitor(ip,date)
		session['visited']=True
		db.session.add(v)
		db.session.commit()
	return jsonify({'success':1})
@app.route('/api/visitor/all',methods=['POST'])
def get_visitors():
	uid=session.get('uid')
	is_admin=session.get('admin')
	if(not is_admin):
		return jsonify({'error':'Unauthorized'}),304	
	count=len(Visitor.query.filter_by(date=datetime.utcnow).all())
	return jsonify({'unique_visits_today':count})
@app.route('/api/students/count',methods=['POST'])
def count_students():
	count=len(Users.query.filter_by(student=True).all())
	return jsonify({'student_count':count})
@app.route('/api/subjects/count')
def count_subjects():
	count=len(Subject.query.all())
	return jsonify({'count':count})
@app.route('/api/notifications/get',methods=['POST'])
def get_notification():
	uid=session.get('uid')
	is_admin=session.get('admin')
	if(not is_admin):
		return jsonify({'error':'Unauthorized'}),304	
	notifs=Notification().query.filter_by(date=datetime.utcnow)
	return jsonify({'data':notifs})
@app.route('/api/notifications/post',methods=['POST'])
def post_notification():
	if(validate(request.form.get('notif_data'))):
		notif=Notification(request.form.get('notif_data'))
		db.session.add(notif)
		db.session.commit()
		return jsonify({'success':1})
	else:
		return jsonify({'error':'Unauthorized'}),304
@app.route('/api/teachers/all',methods=['POST'])
def get_all_teachers():
	teachers=Users.query.filter_by(teacher=True)
	return jsonify({'data':teachers,'count':len(teachers)})
#@app.route('/api/teachers/add')
#def add_teacher():
#depracated. Use /api/register instead.
@app.route('/api/teachers/edit',methods=['POST'])
def edit_teacher():
	uid=session.get('uid')
	is_admin=session.get('admin')
	if(not is_admin):
		return jsonify({'error':'Unauthorized'}),304	
	id=request.form.get('id')
	data=request.form
	if validate(id):
		user=Users.query.filter_by(id=id).first()
		user.first_name=data.get('first_name')
		user.last_name=data.get('last_name')
		user.email=data.get('email')
		user.password=generate_password_hash(data.get('password'))
		user.admin=data.get('admin')
		user.teacher=data.get('teacher')
		user.student=data.get('student')
		db.session.commit()
		return jsonify({'success':1})
	else:
		return jsonify({'error':'Unauthorized'}),304	
@app.route('/api/delete',methods=['POST'])
def del_user():
	uid=session.get('uid')
	is_admin=session.get('admin')
	if(not is_admin):
		return jsonify({'error':'Unauthorized'}),304	
	user=Users.query.filter_by(id=id)
	db.session.delete(user)
	db.session.commit()
@app.errorhandler(404)
def err_404(err):
	return render_template('utss/dark/page-404.html')
@app.errorhandler(500)
def err_500(err):
	return render_template('utss/dark/page-500.html')
@app.route('/contact',methods=['POST'])
def contact():
  msg=Message('Thanks for suscribing!', sender =   'info@utss.edu.ng', recipients = [request.form.get('email')])
  msg.body = "Welcome to UTSS.We're glad to have you here."
  msg2=Message('Contact!',sender='info@utss.edu.ng',recepients=['info@utss.edu.ng'])
  msg2.body=f"Subject: {request.form.get('subject')} \n Message: {request.form.get('message')} \n sender: {request.form.get('email')} \n Name: {request.form.get('name')}"
  mail.send(msg2)
  mail.send(msg)
  suscriber=Suscriber(request.form.get('email'),request.form.get('name'))
  db.session.add(suscriber)
  db.session.commit()
  return jsonify({'success':1})
if __name__=='__main__':
	app.run(debug=True)