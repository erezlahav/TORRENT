import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Sender and Receiver Email
def send_Email_Verification(sender_email, receiver_email, verfication_password):
    password = "wjen rspt cvih csfe"  # Use App Password, NOT your Gmail password!

    # Create Email
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = "Verify your password"
    msg.attach(MIMEText("Verfication Password : " + verfication_password, "plain"))

    # Connect to Gmail SMTP Server and Send Email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Secure the connection
        server.login(sender_email, password)  # Login to the SMTP server
        server.sendmail(sender_email, receiver_email, msg.as_string())  # Send email
        server.quit()
        print("✅ Email sent successfully!")
    except Exception as e:
        print(f"❌ Error: {e}")
