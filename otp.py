
import random
import smtplib
from flask import Flask, current_app
from flask_mysqldb import MySQL

app = Flask(__name__)

mysql = MySQL(app)


def generate_otp():
    return ''.join([str(random.randint(0, 9)) for i in range(4)])


def send_otp_email(email, otp):
    
    email_sender = 'abc@gmail.com'  # Replace with your Gmail email address
    email_password = ''  # Replace with your Gmail password or app password

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()

    server.login(email_sender, email_password)

    msg = 'Hello, Your OTP is ' + str(otp)

    server.sendmail(email_sender, email, msg)

    server.quit()

if __name__ == '__main__':
    with app.app_context():
        email = 'users[2]'  # Set the receiver email address
        otp = generate_otp()
        send_otp_email(email, otp)

