# Password Storing Website
from flask import Flask, render_template, url_for, redirect, flash, session
from info import RegisterForm, LoginForm, DetailsForm, SearchForm
from flask_ckeditor import CKEditor
from flask_bootstrap import Bootstrap5 
import mysql.connector
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

#.......................Database Connection............................
mydb = mysql.connector.connect(host = "localhost", user = "root", password = "My@123prad")
mycursor = mydb.cursor()
database_name = "password_web"
query = "SELECT schema_name FROM information_schema.schemata WHERE schema_name = %s"
mycursor.execute(query, (database_name,))
result = mycursor.fetchone()
if result:
    print('present')
    mycursor.execute(f"use {database_name}")
else:
    if not result:
            mycursor.execute(f"CREATE DATABASE {database_name}")
            print(f"The database '{database_name}' has been created.")
            mycursor.execute(f"use {database_name}")
            mydb.commit()

#........................Table Connection.............................
tables_to_check = ["person_data", "website"]
query = "SHOW TABLES LIKE %s"
mycursor.execute(query, (tables_to_check[0],))
result = mycursor.fetchone()
if result:
    print('present')
else:
    if not result:
            mycursor.execute(f"CREATE TABLE {tables_to_check[0]} (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, password VARBINARY(255) NOT NULL)")
            print(f"The database '{tables_to_check[0]}' has been created.")
            mydb.commit()

query = "SHOW TABLES LIKE %s"
mycursor.execute(query, (tables_to_check[1],))
result = mycursor.fetchone()
if result:
    print('present')
else:
    if not result:
            mycursor.execute(f"CREATE TABLE {tables_to_check[1]} (id INT AUTO_INCREMENT PRIMARY KEY, pid INT ,email VARCHAR(255) NOT NULL, web_name VARCHAR(255) NOT NULL, password VARBINARY(255) NOT NULL,  FOREIGN KEY (pid) REFERENCES {tables_to_check[0]}(id))")
            print(f"The database '{tables_to_check[1]}' has been created.")
            mydb.commit()

#........................Encryption.............................
def key_generate():
    salt = b'\xcf\x87\xfb\xfd\x1c\xbbx\xa7'
    password= 'not known'
    key = PBKDF2(password, salt, dkLen=8)
    return key

def  Encrypt(password):
    key = key_generate()
    cipher = DES.new(key, DES.MODE_ECB)
    # Encrypt the password
    padded_password = pad(password.encode(), DES.block_size)
    enc_pass = cipher.encrypt(padded_password)
    return enc_pass 

#........................Decryption.............................
def  Decrypt(password):
    key = key_generate()

    cipher = DES.new(key, DES.MODE_ECB)
    # Decrypt the password
    decrypted_data = cipher.decrypt(password)
    unpadded_data = unpad(decrypted_data, DES.block_size).decode()
    return unpadded_data

#........................Actual Code.............................

app = Flask(__name__)
app.config['SECRET_KEY'] = "123456asamd"
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)# initialise bootstrap-flask 

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login_page():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        epassword = Encrypt(login_form.password.data)
        print(epassword)
        query = f"SELECT * FROM {tables_to_check[0]} WHERE email = %s AND password = %s"
        mycursor.execute(query, (login_form.email.data, epassword))
        user = mycursor.fetchone()

        if user:
            flash("You have Logged in successfully!")
            return redirect(url_for('details_page', user_id = user[0]))
        else:
            flash("You have not registered! Please register first.")
            return redirect(url_for('register_page'))
        
    return render_template('login.html', form=login_form, output = 0)



@app.route('/register', methods=["GET", "POST"])
def register_page():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if register_form.password.data == register_form.re_password.data :
            epassword = Encrypt(register_form.password.data)
            print(epassword)
            sql = f"insert into {tables_to_check[0]} (username, email, password) values (%s, %s, %s)"
            val = (register_form.name.data, register_form.email.data, epassword)
            mycursor.execute(sql, val)
            mydb.commit()

            # dpassword = Decrypt(register_form.password.data)
            query = f"SELECT id FROM {tables_to_check[0]} WHERE email = %s AND password = %s"
            mycursor.execute(query, (register_form.email.data, epassword))
            user_id = mycursor.fetchone()
            flash("You have registered successfully!")
            return redirect(url_for('details_page', user_id = user_id[0]))
        else:
            flash("Password Doesn't matched!")
            return render_template("register.html", form = register_form)
    return render_template("register.html", form = register_form)


@app.route('/details/<int:user_id>', methods=["GET", "POST"])
def details_page(user_id):
    details_form = DetailsForm()
    if details_form.validate_on_submit():
        if details_form.password.data == details_form.re_password.data :
            epassword = Encrypt(details_form.password.data)
            print(epassword)
            sql = f"insert into {tables_to_check[1]} (pid, email, web_name, password) values (%s, %s, %s, %s)"
            val = (user_id, details_form.email.data, details_form.web_name.data, epassword)
            mycursor.execute(sql, val)
            mydb.commit()
            # Consume any leftover result sets
            mycursor.fetchall()
            flash("Data Entered Successfully!")
            return redirect(url_for('details_page', user_id=user_id))
        else:
            flash("Password Doesn't matched!")
            return render_template("details.html", user_id = user_id, form = details_form)
    return render_template("details.html", user_id = user_id, form = details_form)


@app.route('/search/<user_id>', methods=["GET", "POST"])
def search_page(user_id):
    session.pop('data_id', None)
    search_form = SearchForm()
    if search_form.validate_on_submit():
        query = f"SELECT * FROM {tables_to_check[1]} WHERE pid = %s AND email = %s AND web_name = %s"
        try:
            mycursor.execute(query, (user_id, search_form.email.data, search_form.web_name.data))
            user = mycursor.fetchone()
            if user:
                session['data_id'] = user[0]
                return redirect(url_for('showdata_page',user_id=user_id, data_id = user[0]))
            else:
                flash("Data not found!", "warning")
        except Exception as e:
            flash("Data Not Present!")
            print("An error occurred:", e)
            return redirect(url_for('search_page', user_id=user_id))
    return render_template("search.html", form = search_form, user_id=user_id)



@app.route('/showdata/<user_id>/<data_id>')
def showdata_page(user_id, data_id):
    query = f"SELECT email, web_name, password FROM {tables_to_check[1]} WHERE pid = %s AND id = %s"
    try:
        mycursor.execute(query, (user_id, data_id))
        result = mycursor.fetchone()

        data = {
                'email': result[0],  # Assuming email is the second column (index 1)
                'web_name': result[1],  # Assuming web_name is the third column (index 2)
                'password': Decrypt(result[2])  # Assuming password is the fourth column (index 3)
        }
        return render_template("show_data.html", data=data, user_id=user_id)
    except Exception as e:
        print("An error occurred:", e)
        # flash("Data Not Present!")
        return redirect(url_for('search_page', user_id=user_id))

if __name__ =="__main__":
    app.run(debug=True, port=5002)






































