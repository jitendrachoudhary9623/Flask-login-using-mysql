from flask import Flask,render_template,request,session,logging,url_for,redirect,flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker

from passlib.hash import sha256_crypt

engine=create_engine("mysql+pymysql://root:root@localhost/register") #dbname usernamee:password@localhost/register
db=scoped_session(sessionmaker(bind=engine))
app = Flask(__name__)

@app.route("/")
def home():
	return render_template("home.html")

@app.route("/register",methods=["GET","POST"])
def register():
	if request.method == "POST":
		name=request.form.get("name")
		username=request.form.get("username")
		password=request.form.get("password")
		confirm=request.form.get("confirm")
		secure_password=sha256_crypt.encrypt(str(password))
		
		if password == confirm:
			db.execute("INSERT INTO users(name,username,password) VALUES (:name,:username,:password)",{"name":name,"username":username,"password":secure_password})
			db.commit()
			flash("Registeration successfull , Please Login ","success")
			return redirect(url_for('login'))
		else:
			flash("Password does not match","danger")
			return render_template('register.html')
	return render_template("register.html")


@app.route("/login",methods=["GET","POST"])
def login():
	if request.method=="POST":
		uname=request.form.get("username")
		password=request.form.get("password")
		userdata=db.execute("SELECT username FROM users where username=:uname",{"uname":uname}).fetchone()
		passdata=db.execute("SELECT password FROM users where username=:uname",{"uname":uname}).fetchone()

		if userdata is None:
			flash("No user found please check your username","danger")
			return render_template("login.html")
		else:
			for pd in passdata:
				if sha256_crypt.verify(password,pd):
					session["log"]=True
					flash("Welcome back {} ".format(userdata[0]),"success")
					return redirect(url_for("home"))
				else:
					flash("Wrong password","danger")
					return render_template("login.html")
	return render_template("login.html")

@app.route("/logout")
def logout():
	session["log"]=False
	session.clear()
	flash("Logged out ,Thank you for using our service","success")
	return redirect(url_for("login"))

if __name__=="__main__":
	app.secret_key="interviewbot"
	app.run(debug=True)
