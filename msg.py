
import smtplib
def send_message_email(email, msg):

    email_sender = 'abc@gmail.com'  # Replace with your Gmail email address
    email_password = ''  # Replace with your Gmail password or app password

    server = smtplib.SMTP('smtp.gmail.com', 587)

    server.starttls()

    server.login(email_sender, email_password)

    server.sendmail(email_sender, email, msg)

    server.quit()

if __name__ == '__main__':

    email = 'users[2]'  # Set the receiver email address
    message = 'Hello, Course has been Added/Updated!'  # Set your message
    send_message_email(email, message)  # Send the message via email
