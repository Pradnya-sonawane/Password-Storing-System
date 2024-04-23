from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired #, URL
# from flask_ckeditor import CKEditorField

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    re_password = PasswordField("Re-Enter Password", validators=[DataRequired()])
    name = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class DetailsForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    web_name = StringField("Website Name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    re_password = PasswordField("Re-Enter Password", validators=[DataRequired()])
    submit = SubmitField("Submit!")

class SearchForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    web_name = StringField("Website Name", validators=[DataRequired()])
    submit = SubmitField("Search")



