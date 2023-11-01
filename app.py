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
        '''if users.role == "teacher":
            return redirect(url_for('t_courses'))
        else:

            return redirect(url_for('student_dashboard'))'''
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
                app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:''@localhost/data'
                app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

                # Creating model table for our CRUD database
                class Data(Model):
                    id = Column(db.Integer, primary_key=True)
                    name = Column(String(100))
                    author = Column(String(100))

                    def __init__(self, name, author):
                        self.name = name
                        self.author = author

                # This is the index route where we are going to
                # query on hogwarts student data
                @app.route('/')
                def index():
                    all_data = Data.query.all()

                    return render_template("index.html", students=all_data)

                # this route is for inserting data to mysql database via html forms
                # ...

                # This route is for inserting data to the MySQL database via HTML forms

                # This route is for inserting data to the MySQL database via HTML forms
                # New CRUD routes for teachers
                @app.route('/teacher/insert', methods=['POST'])
                def teacher_insert():
                    if request.method == 'POST':
                        user_id = session.get('user_id')
                        if user_id:
                            cursor = mysql.connection.cursor()
                            cursor.execute("SELECT role FROM users WHERE id=%s", (user_id,))
                            user = cursor.fetchone()
                            cursor.close()

                            if user and user[0] == 'teacher':
                                # Implement the insert operation for teachers
                                name = request.form['name']
                                author = request.form['author']
                                my_data = Data(name, author)
                                session.add(my_data)
                                session.commit()

                                flash("Book Inserted Successfully")

                                return redirect(url_for('index'))
                            else:
                                flash("You must be a teacher to perform this action.")
                                return redirect(url_for('index'))

                # Implement similar routes for update and delete operations for teachers

                # This is our update route where we are going to update student data
                @app.route('/update', methods=['GET', 'POST'])
                def update():
                    if request.method == 'POST':
                        user_id = session.get('user_id')
                        if user_id:
                            cursor = mysql.connection.cursor()
                            cursor.execute("SELECT role FROM users WHERE id=%s", (user_id,))
                            user = cursor.fetchone()
                            cursor.close()

                            if user and user[0] == 'teacher':
                                my_data = Data.query.get(request.form.get('id'))

                                my_data.name = request.form['name']
                                my_data.author = request.form['author']

                                session.commit()
                                flash("Book Updated Successfully")

                                return redirect(url_for('index'))
                            else:
                                flash("You must be a teacher to perform this action.")
                                return redirect(url_for('Index'))  # Redirect to a suitable page for non-teachers

                # This route is for deleting student records
                @app.route('/delete/<id>/', methods=['GET', 'POST'])
                def delete(id):
                    user_id = session.get('user_id')
                    if user_id:
                        cursor = mysql.connection.cursor()
                        cursor.execute("SELECT role FROM users WHERE id=%s", (user_id,))
                        user = cursor.fetchone()
                        cursor.close()

                        if user and user[0] == 'teacher':
                            my_data = Data.query.get(id)
                            session.delete(my_data)
                            session.commit()
                            flash("Book Deleted Successfully")

                            return redirect(url_for('index'))
                        else:
                            flash("You must be a teacher to perform this action.")
                            return redirect(url_for('index'))  # Redirect to a suitable page for non-teachers
                return redirect(url_for('Index'))
            else:
                return render_template('dashboard.html', user=user)

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
