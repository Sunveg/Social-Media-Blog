from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from firstapp.models import User
from flask_wtf.file import FileField, FileAllowed


class RegistrationForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min = 2, max = 20)])

	password = PasswordField('Password', validators=[DataRequired()])

	confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

	email = StringField('Email', validators=[DataRequired(), Email()])

	submit = SubmitField('Sign up')

	def validate_username(self, username):

		user = User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError('This username is already taken. Please try a different one!')

	def validate_email(self, email):

		user = User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError('This email is already taken. Please try a different one!')


class LoginForm(FlaskForm):

	email = StringField('Email', validators=[DataRequired(), Email()])

	password = PasswordField('Password', validators=[DataRequired()])

	remember = BooleanField('Remember Me')

	submit = SubmitField('Log in') 


class UpdateForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired(), Length(min = 2, max = 20)])

	email = StringField('Email', validators=[DataRequired(), Email()])

	picture = FileField('Profile picture', validators=[FileAllowed(['jpg', 'png'])])

	submit = SubmitField('Update profile')

	def validate_username(self, username):
		if username.data != current_user.username:
			user = User.query.filter_by(username=username.data).first()
			if user:
				raise ValidationError('This username is already taken. Please try a different one!')

	def validate_email(self, email):
		if email.data != current_user.email:
			user = User.query.filter_by(email=email.data).first()
			if user:
				raise ValidationError('This email is already taken. Please try a different one!')


class PostForm(FlaskForm):
	title = StringField('Title', validators=[DataRequired()])

	content = TextAreaField('Content', validators=[DataRequired()])

	submit = SubmitField('Post')


class RequestResetForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])

	submit = SubmitField('Request Password Reset')

	def validate_email(self, email):

		user = User.query.filter_by(email=email.data).first()
		if user is None:
			raise ValidationError('This email is not associated with any account. You need to register first.')


class ResetPasswordForm(FlaskForm):
	password = PasswordField('Password', validators=[DataRequired()])

	confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

	submit = SubmitField('Reset Password')

