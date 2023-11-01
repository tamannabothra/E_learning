from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from otp import generate_otp, send_otp_email
import stripe
app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)
stripe.api_key = 'your_stripe_secret_key'

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    otp = PasswordField("OTP", validators=[DataRequired()])
    role = StringField("Role", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route('/')
def index():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # store data into database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES (%s,%s,%s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html', form=form)



@app.route('/t_courses', methods=['GET', 'POST'])
def t_courses():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data


        # store data into database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO courses (course_name,course_description) VALUES (%s,%s)", (name, email))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('logout'))

    return render_template('t_courses.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # store data into database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES (%s,%s,%s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()
        if users.role == "teacher":
            return redirect(url_for('index'))
        else:

            return redirect(url_for('student_dashboard'))
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            if is_teacher():
         

                app = Flask(__name__)
                app.secret_key = "Secret Key"

                app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/data'
                app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
                
                db = SQLAlchemy(app)
                
                class LoginForm(FlaskForm):
                    email = StringField("Email", validators=[DataRequired(), Email()])
                    password = PasswordField("Password", validators=[DataRequired()])
                    submit = SubmitField("Login")
                # Creating model table for our CRUD database
                class Data(db.Model):
                    id = db.Column(db.Integer, primary_key=True)
                    name = db.Column(db.String(100))
                    author = db.Column(db.String(100))
                    price = db.Column(db.Integer)
                    def __init__(self, name, author , price):
                        self.name = name
                        self.author = author
                        self.price = price
                
                # This is the index route where we are going to
                # query on hogwarts student data
                @app.route('/')
                def index():
                    all_data = Data.query.all()
                
                    return render_template("index.html", students=all_data)
        
                
                @app.route('/insert', methods=['POST'])
                def insert():
                    if request.method == 'POST':
                        name = request.form['name']
                        author = request.form['author']
                        price = request.form['price']
                
                        my_data = Data(name, author , price)
                        db.session.add(my_data)
                        db.session.commit()
                
                        flash("Course Inserted Successfully")
                
                        return redirect(url_for('index'))
                
                
                # this is our update route where we are going to update student data
                @app.route('/update', methods=['GET', 'POST'])
                def update():
                    if request.method == 'POST':
                        my_data = Data.query.get(request.form.get('id'))
                
                        my_data.name = request.form['name']
                        my_data.author = request.form['author']
                        my_data.price = request.form['price']
                
                        db.session.commit()
                        flash("Course Updated Successfully")
                
                        return redirect(url_for('index'))
                
                
                # This route is for deleting student records
                @app.route('/delete/<id>/', methods=['GET', 'POST'])
                def delete(id):
                    my_data = Data.query.get(id)
                    db.session.delete(my_data)
                    db.session.commit()
                    flash("Course Deleted Successfully")
                
                    return redirect(url_for('index'))
                
                @app.route('/logout')
                def logout():
                    session.pop('id', None)
                    flash("You have been logged out successfully.")
                    return redirect(url_for('login'))
                
                @app.route('/login', methods=['GET', 'POST'])
                def login():
                    form = LoginForm()
                    if form.validate_on_submit():
                        email = form.email.data
                        password = form.password.data
                
                        cursor = mysql.connection.cursor()
                        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
                        user = cursor.fetchone()
                        cursor.close()
                        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                            session['user_id'] = user[0]
                            return redirect(url_for('dashboard'))
                        else:
                            flash("Login failed. Please check your email and password")
                            return redirect(url_for('login'))
                
                    return render_template('login.html', form=form)
                
                    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

@app.route('/about')
def about():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('about.html', user=user)

    return redirect(url_for('login'))

@app.route('/contact')
def contact():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('contact.html', user=user)

    return redirect(url_for('login'))

@app.route('/courses')
def courses():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            return render_template('courses.html', user=user)

    return redirect(url_for('login'))

@app.route('/generate_and_send_otp', methods=['GET', 'POST'])
def generate_and_send_otp():
    if request.method == 'POST':
        email = request.form['email']  # Retrieve the user's email

        # Generate OTP
        otp = generate_otp()
        session['otp'] = otp  # Store OTP in the session

        # Send OTP via email
        send_otp_email(email, otp)

        flash("OTP sent to your email address.")
        return redirect(url_for('register'))

    return render_template('login.html')

@app.route('/charge', methods=['GET'])
def charge():
    return render_template('charge.html')

@app.route('/msg', methods=['GET', 'POST'])
def generate_and_send_otp():
    if request.method == 'POST':
        flash("updates msg sent .")
        return redirect(url_for('register'))

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
