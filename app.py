from crypt import methods
from encodings import utf_8
from random import randint
from ast import And
from email import message
from random import randint
from flask import Flask, url_for, render_template, request, redirect, session, json
from flask_sqlalchemy import SQLAlchemy
from flask_login import  UserMixin, current_user
from sqlalchemy import false, true
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin , AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_recaptcha import ReCaptcha
from flask_wtf import RecaptchaField
from flask_mail import *
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import time
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
recaptcha = ReCaptcha(app=app)



'''
app.config['MAIL_SERVER ']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = params['gmail-user']
app.config['MAIL_PASSWORD'] = params['gmail-pass']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
'''


app.config.update(dict(
    RECAPTCHA_ENABLED = True,
    RECAPTCHA_SITE_KEY = "6LcaCiUeAAAAAE8c5Eb3ADVw-7UPybPHppPl7kpv",
    RECAPTCHA_SECRET_KEY = "6LcaCiUeAAAAAI5X0blM8ghaB4mzElzJa9hHQw5p",
    ))
 
recaptcha = ReCaptcha()
recaptcha.init_app(app)




class User(UserMixin ,db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100))
    lname = db.Column(db.String(100))
    email = db.Column(db.String(100), primary_key=True)
    password = db.Column(db.String(100))

    def __init__(self, fname, lname, email, password):
        self.fname = fname
        self.lname = lname
        self.email = email
        self.password = password


@app.route('/', methods=['GET','POST'])
def index():
    if session.get('logged_in'):
        #user=session['user']
        return redirect(url_for('home'))
    else:
        return render_template('index.html', message="Hello!")


@app.route('/home/',methods=['GET','POST'])
def home():
    return render_template('home.html')
'''
@app.route('/email/',methods=['GET','POST'])
def email():
    return render_template('email.html')
'''
'''
@app.route('/verify', methods=['GET','POST'])
def verify():
    mails = request.form['email']
    msg = Message('OTP', sender='devnpatel18@gnu.ac.in', recipients=[mails])
    msg.body= str(otp)
    mail.send(msg)
    return render_template('verify.html')
'''


app.config.from_pyfile('config.cfg')
mail = Mail(app)
s = URLSafeTimedSerializer('Thisisasecret!')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email=request.form['email']
        user = User.query.filter_by(email=email).first()
        if not user:
            #password=request.form['password'], cnfpassword=request.form['cnfpassword'] 
            password, cnfpassword=request.form['password'], request.form['cnfpassword']
            if(password==cnfpassword):
                fname=request.form['fname']
                lname=request.form['lname']
                email=request.form['email'] 
                password=generate_password_hash(password, method='sha256')

                token = s.dumps(email,  salt='email-confirm')
                tokens = s.dumps(fname)
                tokenss = s.dumps(lname)
                tokensss = s.dumps(password)

                msg = Message('Confirm Email', sender='playpubg34@gmail.com', recipients=[email])
                link = url_for('confirm_email', fname=tokens, lname=tokenss, password=tokensss, token=token, _external=True)
                msg.body = 'Your link is {}'.format(link)
                mail.send(msg)

                #db.session.add(User(fname=request.form['fname'], lname=request.form['lname'], email=request.form['email'], password=generate_password_hash(password, method='sha256')))
                #db.session.commit()
                return redirect(url_for('login'))
            else:
                return render_template('register.html', message="Please confirm proper password")
        else:
            return render_template('register.html', message="User Already Exists")
    else:
        return render_template('register.html')
        
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        
        email = s.loads(token, salt='email-confirm', max_age=120)
        fname = s.loads(request.args.get('fname'))
        #fname = request.args.get('fname')
        lname =  s.loads(request.args.get('lname'))
        password =  s.loads(request.args.get('password'))
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    ml = User.query.filter_by(email=email).first()
    if ml:
        return render_template('emailalreadyconfirm.html')
    else:
        #ml.confirmed = True
        new_ml = User(email=email, fname=fname, lname=lname, password=password) 
        db.session.add(new_ml)
        db.session.commit()
        return render_template('emailverification.html')
        #return '<h1>The token works!</h1>'



generate = 0
@app.route('/login', methods=['GET', 'POST'])
def login():
    global generate
    if request.method == 'GET':
        return render_template('login.html')
    else:
        email = request.form['email']
        password = request.form['password']
        

        data = User.query.filter_by(email=email).first()


        if (data and check_password_hash(data.password, password)) and recaptcha.verify():
            otp = randint(1000, 9999)
            generate = otp
            msg = Message('Confirm Email', sender='playpubg34@gmail.com', recipients=[email])
            msg.body = str(generate) #'Your link is {}'.format(link)
            mail.send(msg)
            smail = s.dumps(email)
            return redirect(url_for('confirm', email=smail))
            #return redirect('/confirm')
            #session['logged_in'] = True
            #return redirect(url_for('index'))
        elif(data==None):
            return render_template('login.html',message="Email is not registered")
        elif not (data and check_password_hash(data.password, password)):
            return render_template('login.html',message="Email and password don't match")
    
        return render_template('login.html', message="Recheck the Field") 



@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    return redirect(url_for('index'))


'''
@app.route('/em', methods=['GET', 'POST'])
def indexs():
    if request.method == 'GET':
        return render_template('email.html')
    #    return '<form action="/em" method="POST"><input name="email"><input type="submit"></form>'

    email = request.form['email']
    #token = s.dumps(email, salt='email-confirm')

    msg = Message('Confirm Email', sender='devnpatel18@gnu.ac.in', recipients=[email])

    #link = url_for('confirm_email', token=token, _external=True)

    msg.body = str(otp) #'Your link is {}'.format(link)

    mail.send(msg)

    return redirect('/confirm')

    #return '<h1>The email you entered is {}.</h1>'.format(email) 
'''




generated_otp = 0

@app.route('/resend', methods=['GET', 'POST'])
def resend():
    
    global generated_otp
    #email = request.args.get('email')
    if request.method == 'GET':
       return render_template('resend.html')
       #return render_template('verify.html')
    
    newotp = randint(1000, 9999)
    generated_otp=newotp 
    mails = request.form['email']
    msg = Message('Confirm Email', sender='playpubg34@gmail.com', recipients=[mails])
    msg.body = str(newotp) #'Your link is {}'.format(link)
    mail.send(msg)
    #return redirect(url_for('confirm', email=email))
    return redirect('/confirm')



@app.route('/confirm', methods=['GET', 'POST'])
def confirm():
    global generated_otp
    global generate
    #email = s.loads(request.args.get('email'))
    if request.method == 'GET':
        return render_template('verify.html')
     

    userotp=request.form['otp']
    if generate== int(userotp):
        session['logged_in'] = True
        return redirect(url_for('index'))
    elif generated_otp == int(userotp):
        session['logged_in'] = True
        return redirect(url_for('index'))
    else:
        return redirect('/confirm')
        #return render_template('home.html')


'''       #return " Email verified Success" 
generated_otp = 0
@app.route('/resend', methods=['GET'])
def resend():
    
    global generated_otp
    #email = 'devnpatel18gnu.ac.in'
    email = request.args.get('email', None)
    print(email)
    #URLDecoder.decode( email, "UTF-8" )
    newotp = randint(1000, 9999)
    generated_otp=newotp 
    msg = Message('Confirm Email', sender='playpubg34@gmail.com', recipients=[email])
    msg.body = str(newotp) #'Your link is {}'.format(link)
    mail.send(msg)
    return redirect('/confirm')

  '''  




admin = Admin(app)
admin.add_view(ModelView(User, db.session))


if(__name__ == '__main__'):
    app.secret_key = "ThisIsNotASecret:p"
    db.create_all()
    app.debug = 1
    app.run()