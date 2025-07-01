from flask import render_template,url_for,flash,redirect,request
from app1.form import RegistrationForm,LoginForm,UpdateAccountForm
from app1.models import User,Post
from app1 import app,db,bcrypt
from flask_login import login_user,current_user,logout_user,login_required
import secrets
from PIL import Image
import os
posts=[
    {
        'Author':'Furkan Khan',
        'Title':'Billi meow meow',
        'Content':'Cat do bhaw bhaw and dog do meow meow',
        'Date':'June 29 2025'
    },
    {
        'Author':'Shaista Iqbal',
        'Title':'Power of black magic',
        'Content':'100rs and your work done',
        'Date':'June 29 2025'
    }
]

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html',posts=posts)

@app.route("/about")
def about():
    return render_template('about.html',title='About')

@app.route("/register",methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=RegistrationForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data.encode('utf-8'))
        user=User(username=form.username.data,email=form.email.data,password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}!','success')
        return redirect(url_for('login'))
    return render_template('register.html',title='register',form=form)


@app.route("/login",methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
            login_user(user,remember=form.remember.data)
            next_page=request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash(f'Nikal Bsdk!!','danger')
    return render_template('login.html',title='login',form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture):
    random_hex=secrets.token_hex(8)
    _,f_ext=os.path.splitext(form_picture.filename)
    picture_fn=random_hex+ f_ext
    picture_path=os.path.join(app.root_path,'static\profile_pic',picture_fn)
    output_size=(125,125)
    i=Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn



@app.route("/account",methods=['GET','POST'])
@login_required
def account():
    form=UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file=save_picture(form.picture.data)
            current_user.image_file=picture_file
        current_user.username=form.username.data
        current_user.email=form.email.data
        db.session.commit()
        flash('Your account has been updated!','success')
        return redirect(url_for('account'))
    elif request.method=='GET':
        form.username.data=current_user.username
        form.email.data=current_user.email
    ##logout_user()
    image_file=url_for('static',filename='profile_pic/'+current_user.image_file)
    return render_template('account.html',title='Account',image_file=image_file,form=form)