import secrets
import os
from PIL import Image
from flask import url_for, redirect, render_template, request, session, flash, abort
from firstapp.forms import RegistrationForm, LoginForm, UpdateForm, PostForm, RequestResetForm, ResetPasswordForm
from firstapp.models import User, Post
from firstapp import app, bcrypt, db
from flask_login import login_user, current_user, logout_user, login_required


posts = [

{
	"author":"Sunveg Nalwar",
	"title":"Manchester City Overturn their ban?",
	"date_posted":"20 Jan, 2020",
	"content":"Manchester City's bid to overturn their European ban could end with Liverpool in the dock over allegations that they hacked into the Etihad’s scouting database.City will leave nothing off the table when they attempt to beat the sanction",
	"time":"04:36"
},
{
	"author":"City Xtra",
	"title":"City Xtra Podcast",
	"date_posted":"24 May, 2020", 
	"content":"""NEW: The City Xtra Podcast | #2 - Kings of the Carabao

				Speaker with three sound waves Featuring:
				Flag of Spain The Madrid Review
				Crown Pride of the Carabao
				Honeybee The Derby Looms

				Police cars revolving light Available now!""",
	"time":"18:27"
}

]

@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			return redirect(url_for("feed"))
		else:
			flash("Login unsuccessful! Check email and password", "danger")
	return render_template("login.html", title="Log in", form = form)

@app.route("/register", methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
		db.session.add(user)
		db.session.commit()
		flash(f'Account created for {form.username.data}! You are now able to Log in', 'success')
		return redirect(url_for("login"))
	elif request.method == "POST":
		flash('You entered some wrong info', 'danger')
		return render_template("register.html", title="Sign up", form = form)
	else:
		return render_template("register.html", title="Sign up", form = form)

@app.route("/user")
def user():
	if "user" in session:
		user = session["user"]
		flash("You are now logged in !", "info")
		return render_template("home.html", user=user)
	else:
		return redirect(url_for("login"))

@app.route("/logout")
def logout():
	flash("You have been logged out!", "danger")
	logout_user()
	return redirect(url_for("login"))

@app.route("/feed")
@login_required
def feed():
	page = request.args.get('page', 1, type=int)
	posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page = 5)
	return render_template("feeds.html", posts = posts, title="Posts")

def save_picture(form_picture):
	random_hex = secrets.token_hex(8)
	_, f_ext = os.path.splitext(form_picture.filename)
	picture_fn = random_hex + f_ext
	picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

	output_size = (125, 125)
	i = Image.open(form_picture)
	i.thumbnail(output_size)

	i.save(picture_path)

	return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
	form = UpdateForm()
	if form.validate_on_submit():
		if form.picture.data:
			mypicture = save_picture(form.picture.data)
			current_user.image_file = mypicture

		current_user.username = form.username.data
		current_user.email = form.email.data
		db.session.commit()
		flash('Your account has been updated!', 'success')
	elif request.method == 'GET':
		form.username.data = current_user.username
		form.email.data = current_user.email
	image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
	return render_template("account.html", title="Account", image_file=image_file, form=form)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
	form = PostForm()
	if form.validate_on_submit():
		post = Post(title=form.title.data, content=form.content.data, author=current_user)
		db.session.add(post)
		db.session.commit()
		flash('Your post has been created!', 'success')
		return redirect(url_for('feed'))
	return render_template("create_post.html", title="New Post", form=form, legend="New Post")


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
@login_required
def post(post_id):
	post = Post.query.get_or_404(post_id)
	return render_template("post.html", title=post.title, post=post)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.content = form.content.data
		db.session.commit()
		flash('Your post has been updated!', 'success')
		return redirect(url_for('post', post_id=post.id))
	elif request.method == "GET":
		form.title.data = post.title
		form.content.data = post.content
	return render_template("create_post.html", title="Update Post", form=form, legend="Update Post")



@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	db.session.delete(post)
	db.session.commit()
	flash('Your post has been deleted!', 'success')
	return redirect(url_for('feed'))


@app.route("/user/<string:username>")
@login_required
def user_posts(username):
	page = request.args.get('page', 1, type=int)
	user = User.query.filter_by(username=username).first_or_404()
	posts = Post.query.filter_by(author=user)\
			.order_by(Post.date_posted.desc())\
			.paginate(page=page, per_page = 5)
	return render_template("user_posts.html", posts = posts, title=username+"'s Posts", user=user)


def send_reset_email(user):
	pass


app.route("/request_password", methods=['GET', 'POST'])
def reset_request():
	if current_user.is_authenticated:
		return redirect(url_for('feed'))
	form = RequestResetForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		send_reset_email(user)
		flash('An email has been sent with instructions to reset your password', 'info')
		return redirect(url_for('login'))
	return render_template('reset_request.html', title="Reset Password", form=form)

app.route("/request_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
	if current_user.is_authenticated:
		return redirect(url_for('feed'))
	user = User.verify_reset_token(token)
	if user is None:
		flash('Invalid or expired token', 'warning')
		return redirect(url_for('reset_request'))
	form = ResetPasswordForm()
	return render_template('reset_token.html', title="Reset Password", form=form)