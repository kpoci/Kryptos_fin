
import os
import MySQLdb
from MySQLdb.cursors import DictCursor
from flask_mysqldb import MySQL
from argon2 import PasswordHasher
from argon2 import exceptions
from cryptography.fernet import Fernet, InvalidToken
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import argon2
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import re
import traceback
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s:%(message)s'
)
logger = logging.getLogger(__name__)

def is_password_strong(password):
    # At least 8 characters
    if len(password) < 8:
        return False
    # Contains both uppercase and lowercase letters
    if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password):
        return False
    # Contains digits
    if not re.search(r'\d', password):
        return False
    # Contains special characters (excluding spaces)
    if not re.search(r'[^\w\s]', password):
        return False
    # Password is strong
    return True

def send_email(to_email, subject, message):
    sender_email = "bot067744@gmail.com"
    sender_password = "ytwj euls irhw nrzo"  # Use a real app password or environment-secured password
    sender_name = "verificationbot"

    # Create MIMEText message
    msg = MIMEText(message, 'html')
    msg['Subject'] = subject
    msg['From'] = f"{sender_name} <{sender_email}>"
    msg['To'] = to_email

    # Send email via SMTP
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print("Failed to send email:", e)
        raise #For raising the exception

app = Flask(__name__)
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = "users"
app.secret_key = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SECRET KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['WTF_CSRF_ENABLED'] = False

mysql = MySQL(app)

# PasswordHasher instance with custom parameters
ph = PasswordHasher(memory_cost=102400, time_cost=1, parallelism=8)
# Initialize CSRF Protection

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OTPVerificationForm(FlaskForm):
    otp = StringField('OTP', validators=[
        DataRequired(message="Please enter the OTP."),
        Length(min=6, max=6, message='OTP must be exactly 6 digits.'),
        Regexp('^\d{6}$', message='OTP must contain only numbers.')
    ])
    submit = SubmitField('Verify OTP')

class ResendOTPForm(FlaskForm):
    submit = SubmitField('Resend OTP')

#for verify_reset_otp
class OTPVerificationForm(FlaskForm):
    otp = StringField('OTP', validators=[
        DataRequired(message="Please enter the OTP."),
        Length(min=6, max=6, message='OTP must be exactly 6 digits.'),
        Regexp('^\d{6}$', message='OTP must contain only numbers.')
    ])
    verify_submit = SubmitField('Verify')

class ResendOTPForm(FlaskForm):
    resend_submit = SubmitField('Resend OTP')

@app.route('/learn_more_route')
def learn_more_route():
    # Serve the content for the 'learn_more_route' route
    return render_template('learnmore.html')

# Home Route
@app.route('/home')
def home():
    if 'user_id' in session:
        user_id = session['user_id']
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT username FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()
        username = user['username'] if user else "Unknown"
        
        return render_template("home.html", username=username, user_id=user_id)
    else:
        return redirect(url_for('login'))

@app.route("/", methods=["POST", "GET"])
def index():
    return render_template('login.html')

#Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        email = request.form['email']
        master_pass = request.form['master_pass']
        confirm_master_pass = request.form['confirm_master_pass']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        # Validate master password and confirm password match
        if master_pass != confirm_master_pass:
            flash("Master passwords do not match.", "error")
            return redirect(url_for('register'))

        # Validate master password strength
        if not is_password_strong(master_pass):
            flash("Master password is not strong enough.", "error")
            return redirect(url_for('register'))

        # **Check if username already exists**
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT Id FROM accounts WHERE username = %s", (username,))
        user_with_same_username = cur.fetchone()
        cur.close()

        if user_with_same_username:
            flash("Username already exists. Please choose a different username.", "error")
            return redirect(url_for('register'))

        # **Check if email already exists**
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT Id FROM accounts WHERE email = %s", (email,))
        user_with_same_email = cur.fetchone()
        cur.close()

        if user_with_same_email:
            flash("Email already registered. Please use a different email address.", "error")
            return redirect(url_for('register'))

        # Hash the master password and security answer
        hashed_master_pass = ph.hash(master_pass)
        hashed_security_answer = ph.hash(security_answer)

        # Generate email verification token (e.g., UUID or random string)
        email_verification_token = str(uuid.uuid4())

        # Insert the new user into the database with email unverified
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO accounts (username, email, master_pass, security_question, security_answer, email_verified, email_verification_token)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (username, email, hashed_master_pass, security_question, hashed_security_answer, False, email_verification_token))
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            print(f"Error inserting new user: {e}")
            flash("An error occurred during registration. Please try again.", "error")
            return redirect(url_for('register'))

        # Send email verification
        verification_link = url_for('verify_email', token=email_verification_token, _external=True)
        subject = "Email Verification"
        message = f"""
        <p>Hi {username},</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="{verification_link}">{verification_link}</a></p>
        <p>Please do not reply to this email. If you did not request this verification, please contact our support team at djl0466@dlsud.edu.ph.</p>
        <p>Best regards,<br>Kryptos***</p>
        """
        send_email(email, subject, message)

        
        flash("Registration successful! Please check your email to verify your account.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

#verify email
@app.route('/verify_email/<token>')
def verify_email(token):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM accounts WHERE email_verification_token = %s", (token,))
    user = cur.fetchone()
    if user:
        cur.execute("UPDATE accounts SET email_verified = %s, email_verification_token = NULL WHERE Id = %s", (True, user['Id']))
        mysql.connection.commit()
        cur.close()
        flash("Email verified successfully! You can now log in.", "success")
        return redirect(url_for('login'))
    else:
        cur.close()
        flash("Invalid or expired verification link.", "error")
        return redirect(url_for('register'))
    
#recover password
@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form['email']
        try:
            # Check if email exists in the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT * FROM accounts WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user:
                # Generate OTP and expiry time
                otp = random.randint(100000, 999999)
                otp_expiry = datetime.now() + timedelta(minutes=5)

                # Update reset_otp and reset_otp_expiry in the database
                cur = mysql.connection.cursor()
                cur.execute("UPDATE accounts SET reset_otp = %s, reset_otp_expiry = %s WHERE email = %s",
                            (otp, otp_expiry, email))
                mysql.connection.commit()
                cur.close()

                # Send OTP email
                subject = "Your Password Reset OTP"
                message = f"""
                <p>Dear {user['username']},</p>
                <p>Your OTP for password reset is: <strong>{otp}</strong></p>
                <p>This OTP is valid for the next 5 minutes.</p>
                <p>Please do not reply to this email. If you did not request this, please ignore this email.</p>
                <p>Best regards,<br>Kryptos</p>
                """
                send_email(email, subject, message)

                flash("An OTP has been sent to your email address.", "success")
                session['reset_email'] = email  # Store email in session for the next steps
                return redirect(url_for('verify_reset_otp'))
            else:
                flash("Email address not found.", "error")
                return redirect(url_for('recover_password'))
        except Exception as e:
            print(f"Error during password recovery: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('recover_password'))

    return render_template('recover_password.html')   

#verify reset OTP
@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "danger")
        return redirect(url_for('recover_password'))

    form = OTPVerificationForm()
    resend_otp_form = ResendOTPForm()
    email = session['reset_email']

    if request.method == 'POST':
        if form.verify_submit.data and form.validate_on_submit():
            otp_input = form.otp.data

            try:
                with mysql.connection.cursor(DictCursor) as cur:
                    cur.execute("SELECT reset_otp, reset_otp_expiry FROM accounts WHERE email = %s", (email,))
                    user = cur.fetchone()

                    if not user:
                        flash("User not found.", "danger")
                        return redirect(url_for('recover_password'))

                    reset_otp = user.get('reset_otp')
                    reset_otp_expiry = user.get('reset_otp_expiry')

                    if not reset_otp or not reset_otp_expiry:
                        flash("OTP not found. Please request a new one.", "danger")
                        return redirect(url_for('resend_reset_otp'))

                    if datetime.now() > reset_otp_expiry:
                        flash("OTP has expired. Please request a new one.", "danger")
                        return redirect(url_for('resend_reset_otp'))

                    if otp_input == str(reset_otp):
                        session['otp_verified'] = True
                        flash("OTP verified successfully!", "success")
                        return redirect(url_for('security_question'))
                    else:
                        flash("Invalid OTP. Please try again.", "danger")
                        return redirect(url_for('verify_reset_otp'))
            except Exception as e:
                print(f"Error during OTP verification: {e}")
                flash("An error occurred during OTP verification. Please try again.", "danger")
                return redirect(url_for('verify_reset_otp'))

        elif 'resend_submit' in request.form and resend_otp_form.validate_on_submit():
            # Resend OTP logic
            try:
                with mysql.connection.cursor(DictCursor) as cur:
                    # Fetch user info
                    cur.execute("SELECT username FROM accounts WHERE email = %s", (email,))
                    user = cur.fetchone()

                    if not user:
                        flash("User not found.", "danger")
                        return redirect(url_for('recover_password'))

                    # Generate a new OTP
                    otp = random.randint(100000, 999999)
                    otp_expiry = datetime.now() + timedelta(minutes=5)

                    # Update OTP and expiry in the accounts table
                    cur.execute("UPDATE accounts SET reset_otp = %s, reset_otp_expiry = %s WHERE email = %s",
                                (otp, otp_expiry, email))
                    mysql.connection.commit()

                    # Send OTP email
                    subject = "Your OTP for Password Reset (Resent)"
                    message = f"""
                    <p>Dear {user['username']},</p>
                    <p>Your new OTP for password reset is: <strong>{otp}</strong></p>
                    <p>This OTP is valid for the next 5 minutes.</p>
                    <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph</p>
                    <p>Best regards,<br>Kryptos***</p>
                    """
                    send_email(email, subject, message)

                    flash("A new OTP has been sent to your email.", "success")
            except Exception as e:
                mysql.connection.rollback()
                print(f"Error during OTP resend: {e}")
                flash("Failed to resend OTP. Please try again.", "danger")
                return redirect(url_for('verify_reset_otp'))
    else:
        # Fetch user's email to display
        try:
            with mysql.connection.cursor(DictCursor) as cur:
                cur.execute("SELECT email FROM accounts WHERE email = %s", (email,))
                user = cur.fetchone()
                email = user.get('email') if user else 'your email'
        except Exception as e:
            print(f"Error fetching email: {e}")
            email = 'your email'

    return render_template('verify_reset_otp.html', email=email, form=form, resend_otp_form=resend_otp_form)

#resend for reset recovery password
@app.route('/resend_reset_otp', methods=['POST'])
def resend_reset_otp():
    if 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "danger")
        return redirect(url_for('recover_password'))

    email = session['reset_email']
    try:
        cur = mysql.connection.cursor(DictCursor)
        # Fetch user info
        cur.execute("SELECT username FROM accounts WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('recover_password'))

        # Generate a new OTP
        otp = random.randint(100000, 999999)
        otp_expiry = datetime.now() + timedelta(minutes=5)

        # Update OTP and expiry in the accounts table
        cur.execute("UPDATE accounts SET reset_otp = %s, reset_otp_expiry = %s WHERE email = %s",
                    (otp, otp_expiry, email))
        mysql.connection.commit()

        # Send OTP email
        subject = "Your OTP for Password Reset (Resent)"
        message = f"""
        <p>Dear {user['username']},</p>
        <p>Your new OTP for password reset is: <strong>{otp}</strong></p>
        <p>This OTP is valid for the next 5 minutes.</p>
        <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph</p>
        <p>Best regards,<br>Kryptos***</p>
        """
        send_email(email, subject, message)

        flash("A new OTP has been sent to your email.", "success")
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error during OTP resend: {e}")
        flash("Failed to resend OTP. Please try again.", "danger")
    finally:
        cur.close()

    return redirect(url_for('verify_reset_otp'))

#security question
@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    if 'otp_verified' not in session or 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "error")
        return redirect(url_for('recover_password'))

    email = session['reset_email']

    try:
        # Fetch the security question from the database
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT security_question FROM accounts WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            security_question = user['security_question']
        else:
            flash("User not found.", "error")
            return redirect(url_for('recover_password'))
    except Exception as e:
        print(f"Error fetching security question: {e}")
        flash("An error occurred. Please try again.", "error")
        return redirect(url_for('recover_password'))

    if request.method == 'POST':
        security_answer_input = request.form['security_answer']

        try:
            # Fetch the hashed security answer from the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT security_answer FROM accounts WHERE email = %s", (email,))
            user = cur.fetchone()
            cur.close()

            if user:
                security_answer_hash = user['security_answer']

                # Use ph.verify to compare the input with the hashed answer
                try:
                    ph.verify(security_answer_hash, security_answer_input)
                    session['security_verified'] = True
                    return redirect(url_for('reset_password'))
                except exceptions.VerifyMismatchError:
                    # Incorrect security answer
                    flash("Incorrect security answer. Please try again.", "error")
                    return redirect(url_for('security_question'))
                except Exception as e:
                    # Handle other exceptions
                    print(f"Error during security answer verification: {e}")
                    flash("An error occurred. Please try again.", "error")
                    return redirect(url_for('security_question'))
            else:
                flash("User not found.", "error")
                return redirect(url_for('recover_password'))
        except Exception as e:
            print(f"Error during security answer verification: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('security_question'))

    return render_template('security_question.html', security_question=security_question)

#reset_password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'security_verified' not in session or 'reset_email' not in session:
        flash("Session expired. Please start the password recovery process again.", "error")
        return redirect(url_for('recover_password'))

    email = session['reset_email']

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
            return redirect(url_for('reset_password'))

        # Password Requirements Validation
        if len(new_password) < 8 \
           or not re.search(r'[A-Z]', new_password) \
           or not re.search(r'[a-z]', new_password) \
           or not re.search(r'\d', new_password) \
           or not re.search(r'[!@#$%^&*]', new_password):
            flash("Password does not meet the required strength criteria.", "error")
            return redirect(url_for('reset_password'))

        try:
            # Hash the new password
            hashed_password = ph.hash(new_password)

            # Update the user's password in the database
            cur = mysql.connection.cursor()
            cur.execute("UPDATE accounts SET master_pass = %s WHERE email = %s", (hashed_password, email))
            mysql.connection.commit()
            cur.close()

            # Clear the session variables
            session.pop('reset_email', None)
            session.pop('otp_verified', None)
            session.pop('security_verified', None)

            flash("Your password has been reset successfully. You can now log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error resetting password: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html') 

#settings
@app.route('/settings')
def settings():
    return render_template('settings.html')

# Login Route with Enhanced Error Handling, Account Lockout Notification, and Email Verification
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_pass']  # Renamed for clarity

        try:
            # Fetch user from the database
            cur = mysql.connection.cursor(DictCursor)
            cur.execute("SELECT * FROM accounts WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()

            if user:
                # Check if email is verified
                if not user.get('email_verified'):
                    flash("Please verify your email before logging in.", "error")
                    return redirect(url_for('login'))

                # Check if account is locked
                lockout_until = user.get('lockout_until')
                if lockout_until:
                    # Parse lockout_until to datetime if necessary
                    if isinstance(lockout_until, str):
                        try:
                            lockout_until = datetime.strptime(lockout_until, '%Y-%m-%d %H:%M:%S')
                        except ValueError as ve:
                            print(f"Error parsing lockout_until: {ve}")
                            lockout_until = None
                    if lockout_until and datetime.now() < lockout_until:
                        flash("Account is temporarily locked due to multiple failed login attempts. Please try again later.", "error")
                        return redirect(url_for('login'))

                # Proceed with password verification
                try:
                    ph.verify(user['master_pass'], master_password)
                    # Password is correct
                    # Reset failed attempts on successful login
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE accounts SET failed_attempts = 0, lockout_until = NULL WHERE Id = %s", (user['Id'],))
                    mysql.connection.commit()
                    cur.close()

                    # Generate OTP and expiry time
                    otp = random.randint(100000, 999999)
                    otp_expiry = datetime.now() + timedelta(minutes=5)

                    # Update OTP and expiry in the accounts table
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE accounts SET otp = %s, otp_expiry = %s WHERE Id = %s", (otp, otp_expiry, user['Id']))
                    mysql.connection.commit()
                    cur.close()

                    # Send OTP email
                    subject = "Your OTP for Login"
                    message = f"""
                    <p>Dear {user['username']},</p>
                    <p>Your OTP for login is: <strong>{otp}</strong></p>
                    <p>This OTP is valid for the next 5 minutes.</p>
                    <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph.</p>
                    <p>Best regards,<br>Kryptos***</p>
                    """
                    send_email(user['email'], subject, message)
                    
                    session['user_id'] = user['Id']

                    session['temp_user_id'] = user['Id']
                    flash("OTP sent to your email!", "success")
                    return redirect(url_for('otp_verification'))
                except argon2.exceptions.VerifyMismatchError:
                    # Password is incorrect
                    # Increment failed_attempts
                    cur = mysql.connection.cursor()
                    cur.execute("UPDATE accounts SET failed_attempts = failed_attempts + 1 WHERE Id = %s", (user['Id'],))
                    mysql.connection.commit()

                    # Fetch updated failed_attempts
                    cur = mysql.connection.cursor(DictCursor)
                    cur.execute("SELECT failed_attempts FROM accounts WHERE Id = %s", (user['Id'],))
                    updated_user = cur.fetchone()
                    cur.close()
                    failed_attempts = updated_user['failed_attempts']

                    if failed_attempts >= 5:
                        try:
                            # Lock account for 1 day
                            lockout_until = datetime.now() + timedelta(days=1)
                            lockout_until_str = lockout_until.strftime('%Y-%m-%d %H:%M:%S')

                            cur = mysql.connection.cursor()
                            cur.execute("UPDATE accounts SET lockout_until = %s WHERE Id = %s", (lockout_until_str, user['Id']))
                            mysql.connection.commit()
                            cur.close()
                        except Exception as e:
                            print(f"Error updating lockout_until: {e}")
                            traceback.print_exc()
                            flash("An error occurred during login. Please try again.", "error")
                            return redirect(url_for('login'))

                        # Send account lockout email notification
                        try:
                            subject = "Your Account Has Been Locked"
                            message = f"""
                            <p>Dear {user['username']},</p>
                            <p>Your account has been locked due to 5 invalid login attempts.</p>
                            <p>If this was not you, please consider changing your password immediately.</p>
                            <p>You will be able to attempt login again after 1 day.</p>
                            <p>If you need assistance, please contact our support team at djl0466@dlsud.edu.ph.</p>
                            <p>Best regards,<br>Kryptos***</p>
                            """
                            send_email(user['email'], subject, message)
                        except Exception as e:
                            print(f"Error sending lockout email: {e}")
                            traceback.print_exc()
                            # Decide if you want to proceed even if the email fails

                        flash("Account locked due to multiple failed login attempts. Please check your email for more information.", "error")
                    else:
                        remaining_attempts = 5 - failed_attempts
                        flash(f"Incorrect password. {remaining_attempts} attempt(s) remaining.", "error")
                    return redirect(url_for('login'))
                except Exception as e:
                    print(f"Error during password verification: {e}")
                    traceback.print_exc()  # This will print the full traceback
                    flash("An error occurred during login. Please try again.", "error")
                    return redirect(url_for('login'))
            else:
                # Username not found
                flash("Username not found. Please check and try again.", "error")
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during login process: {e}")
            traceback.print_exc()  # This will print the full traceback
            flash("An error occurred during login. Please try again.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')






# OTP Verification Route
@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for('login'))

    form = OTPVerificationForm()
    resend_form = ResendOTPForm()

    if form.validate_on_submit():
        entered_otp = form.otp.data
        user_id = session['temp_user_id']

        try:
            with mysql.connection.cursor(DictCursor) as cur:
                cur.execute("SELECT otp, otp_expiry FROM accounts WHERE Id = %s", (user_id,))
                user = cur.fetchone()

                if not user:
                    flash("User not found.", "error")
                    logger.error(f"User with ID {user_id} not found during OTP verification.")
                    return redirect(url_for('login'))

                stored_otp = user.get('otp')
                otp_expiry = user.get('otp_expiry')

                if not stored_otp or not otp_expiry:
                    flash("OTP not found. Please request a new one.", "error")
                    logger.warning(f"OTP or expiry not found for user ID {user_id}.")
                    return redirect(url_for('resend_otp'))

                if datetime.now() > otp_expiry:
                    flash("OTP has expired. Please request a new one.", "error")
                    logger.info(f"OTP expired for user ID {user_id}.")
                    return redirect(url_for('resend_otp'))

                if entered_otp == str(stored_otp):
                    # OTP is correct
                    session.pop('temp_user_id', None)
                    session['user_id'] = user_id  # Assuming 'user_id' is the key for logged-in users
                    flash("Logged in successfully!", "success")
                    logger.info(f"User ID {user_id} logged in successfully.")
                    return redirect(url_for('home'))
                else:
                    flash("Invalid OTP. Please try again.", "error")
                    logger.warning(f"Invalid OTP entered for user ID {user_id}.")
                    return redirect(url_for('otp_verification'))
        except Exception as e:
            logger.error(f"Error during OTP verification for user ID {user_id}: {e}")
            flash("An error occurred during OTP verification. Please try again.", "error")
            return redirect(url_for('otp_verification'))

    # Fetch user's email to display
    user_id = session['temp_user_id']
    try:
        with mysql.connection.cursor(DictCursor) as cur:
            cur.execute("SELECT email FROM accounts WHERE Id = %s", (user_id,))
            user = cur.fetchone()
            email = user.get('email') if user else 'your email'
    except Exception as e:
        logger.error(f"Error fetching email for user ID {user_id}: {e}")
        email = 'your email'

    return render_template('otp_verification.html', email=email, form=form, resend_form=resend_form)


# Resend OTP Route
@app.route('/resend_otp', methods=['GET','POST'])
def resend_otp():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for('login'))

    user_id = session['temp_user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Fetch user email
        cur.execute("SELECT email, username FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('login'))

        # Generate a new OTP
        otp = random.randint(100000, 999999)
        otp_expiry = datetime.now() + timedelta(minutes=5)

        # Update OTP and expiry in the accounts table
        cur.execute("UPDATE accounts SET otp = %s, otp_expiry = %s WHERE Id = %s", (otp, otp_expiry, user_id))
        mysql.connection.commit()

        # Send OTP email
        subject = "Your OTP for Login (Resent)"
        message = f"""
        <p>Dear {user['username']},</p>
        <p>Your new OTP for login is: <strong>{otp}</strong></p>
        <p>This OTP is valid for the next 5 minutes.</p>
        <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph</p>
        <p>Best regards,<br>Kyrptos***</p>
        """
        send_email(user['email'], subject, message)
        
        flash("A new OTP has been sent to your email.", "success")
        return redirect(url_for('otp_verification'))
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error resending OTP: {e}")
        flash("Failed to resend OTP. Please try again.", "error")
        return redirect(url_for('otp_verification'))
    finally:
        cur.close()
        

#resend otp

def resend_otp():
    if 'temp_user_id' not in session:
        flash("Session expired. Please log in again.", "error")
        logger.warning("Attempt to resend OTP without valid session.")
        return redirect(url_for('login'))

    user_id = session['temp_user_id']

    try:
        with mysql.connection.cursor(DictCursor) as cur:
            # Fetch user email and username
            cur.execute("SELECT username, email FROM accounts WHERE Id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                flash("User not found.", "error")
                logger.error(f"User with ID {user_id} not found during resend OTP.")
                return redirect(url_for('login'))

            # Generate a new OTP
            otp = random.randint(100000, 999999)
            otp_expiry = datetime.now() + timedelta(minutes=5)

            # Update OTP and expiry in the accounts table
            cur.execute("UPDATE accounts SET otp = %s, otp_expiry = %s WHERE Id = %s", (otp, otp_expiry, user_id))
            mysql.connection.commit()
            logger.info(f"Generated new OTP for user {user['username']} (ID: {user_id}).")

            # Send OTP email
            subject = "Your OTP for Login (Resent)"
            message = f"""
            <p>Dear {user['username']},</p>
            <p>Your new OTP for login is: <strong>{otp}</strong></p>
            <p>This OTP is valid for the next 5 minutes.</p>
            <p>Please do not reply to this email. If you did not request this OTP, please contact our support team at djl0466@dlsud.edu.ph.</p>
            <p>Best regards,<br>Kryptos***</p>
            """
            send_email(user['email'], subject, message)
            logger.info(f"Resent OTP email to {user['email']}.")

            flash("A new OTP has been sent to your email.", "success")
            return redirect(url_for('otp_verification'))
    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Error resending OTP for user ID {user_id}: {e}")
        flash("Failed to resend OTP. Please try again.", "error")
        return redirect(url_for('otp_verification'))
        
#UPDATED
@app.route('/passwordvault')
def passwordvault():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Fetch `keys` belonging to the authenticated user
    cur.execute("SELECT key_id, key_name, `key` FROM `keys` WHERE Id = %s", (user_id,))
    categories = cur.fetchall()

    passwords_by_category = {}
    for category in categories:
        key_id = category['key_id']
        key_name = category['key_name']
        encryption_key = category['key']

        fernet = Fernet(encryption_key.encode())  # Ensure the key is in bytes

        # Fetch passwords associated with this key_id
        cur.execute("SELECT password_id, site, login_name, passwords, title FROM passwords WHERE key_id = %s", (key_id,))
        encrypted_passwords = cur.fetchall()

        decrypted_passwords = []
        for password in encrypted_passwords:
            try:
                decrypted_password = fernet.decrypt(password['passwords'].encode()).decode()
                decrypted_passwords.append({
                    'id': password['password_id'],
                    'site': password['site'],
                    'title': password['title'],
                    'login_name': password['login_name'],
                    'passwords': decrypted_password  # Decrypted password
                })
            except InvalidToken:
                decrypted_passwords.append({
                    'id': password['password_id'],
                    'site': password['site'],
                    'title': password['title'],
                    'login_name': password['login_name'],
                    'passwords': "[Decryption Failed]"
                })

        passwords_by_category[key_id] = decrypted_passwords

    cur.close()

    return render_template('passwordvault.html', categories=categories, passwords_by_category=passwords_by_category, user_id=user_id)




@app.route('/fetch_keys', methods=['GET'])
def fetch_keys():

    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT * FROM `keys` WHERE Id = %s", (user_id,))
        keys = cur.fetchall()
        if keys:
            keys_list = [{'key_name': key[2], 'key': key[3]} for key in keys]
            return jsonify({'success': True, 'keys': keys_list})
        else:
            return jsonify({'success': False, 'message': 'No keys found'}), 404
    finally:
        cur.close()

def get_keys_from_database(user_id):
    # Create a new database cursor
    cur = mysql.connection.cursor()
    
    # SQL query to fetch keys
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM `keys` WHERE user_id = %s", (user_id,))
    keys = cur.fetchall()
    cur.close()

    if keys:
        keys_list = [{'key_name': key[1], 'key': key[2]} for key in keys]
        return jsonify({'success': True, 'keys': keys_list})
    else:
        return jsonify({'success': False, 'message': 'No keys found'}), 404

@app.route('/verify_master_password', methods=['POST'])
def verify_master_password():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'User not authenticated'}), 401
    
    master_password = request.form.get('masterPassword')
    # Query the database to get the hashed master password for the user
    cur = mysql.connection.cursor()
    cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
    stored_password = cur.fetchone()
    cur.close()

    if stored_password and ph.verify(stored_password[0], master_password):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Incorrect password'}), 403


@app.route('/button_action', methods=['POST'])
def button_action():
    print("Received POST to /button_action")
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    key_name = request.form['key_name']
    print(f"Attempting to insert key for account_id: {user_id}")  # Log the user_id being used

    return generate_key(key_name, user_id)

def generate_key(key_name, account_id):
    print("Attempting to insert key for account_id:", account_id)  # Debug output

    # First, check if the account ID actually exists in the accounts table
    cur = mysql.connection.cursor()
    cur.execute("SELECT Id FROM accounts WHERE Id = %s", (account_id,))
    if not cur.fetchone():
        cur.close()
        print(f"No account found for ID {account_id}")  # Debug output
        return jsonify({'message': 'No account found with the given ID'}), 400

    key = Fernet.generate_key()
    key_string = key.decode()  # Convert bytes to string for storage

    try:
        cur.execute("INSERT INTO `keys` (id, key_name, `key`) VALUES (%s, %s, %s)", (account_id, key_name, key_string))
        mysql.connection.commit()
        print("Key inserted successfully")  # Success output
        return jsonify({'message': 'Key generated successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Failed to insert into database: {e}")  # Error output
        return jsonify({'message': 'Database insertion failed: ' + str(e)}), 500
    finally:
        cur.close()


@app.route('/fetch_containers', methods=['GET'])
def fetch_containers():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Fetch keys belonging to the user
        cur.execute("SELECT key_id FROM `keys` WHERE Id = %s", (user_id,))
        keys = cur.fetchall()

        if not keys:
            return jsonify({'message': 'No containers found'}), 404

        # Extract key_ids
        key_ids = [key['key_id'] for key in keys]

        # Fetch passwords associated with these key_ids
        format_strings = ','.join(['%s'] * len(key_ids))
        query = f"SELECT site, login_name, title FROM `passwords` WHERE key_id IN ({format_strings})"
        cur.execute(query, tuple(key_ids))
        records = cur.fetchall()

        if not records:
            return jsonify({'message': 'No containers found'}), 404

        containers = []
        for record in records:
            site, login_name, title = record['site'], record['login_name'], record['title']
            containers.append({
                'site': site,
                'login_name': login_name,
                'title': title
            })

        return jsonify({'success': True, 'containers': containers}), 200
    except Exception as e:
        print(f"General error: {str(e)}")
        return jsonify({'message': 'Failed to fetch data: ' + str(e)}), 500
    finally:
        cur.close()

@app.route('/get_keys/<int:user_id>', methods=['GET'])
def get_keys(user_id):
    # Debugging: Check what session and user_id are
    print(f"Session user_id: {session.get('user_id')}, Requested user_id: {user_id}")

    # Check if the user_id in session matches the one in the URL
    if 'user_id' not in session or session['user_id'] != user_id:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    try:
        with mysql.connection.cursor() as cur:
            # Query to fetch keys for the logged-in user
            cur.execute("SELECT key_id, key_name FROM `keys` WHERE Id = %s", (user_id,))
            keys = cur.fetchall()
            print(f"Fetched keys: {keys}")  # Debugging: Check what keys are fetched

            if not keys:
                return jsonify({'success': False, 'message': 'No keys found for the user'}), 404

            return jsonify({'success': True, 'keys': keys}), 200
    except Exception as e:
        print(f"Error fetching keys: {e}")  # Log the error for debugging
        return jsonify({'success': False, 'message': 'An error occurred while fetching keys'}), 500




@app.route('/add_container', methods=['POST'])
def add_container():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    user_id = session['user_id']

    try:
        data = request.get_json()
        title = data.get('title')
        login_name = data.get('login_name')
        password = data.get('password')
        site = data.get('site')
        key_id = int(data.get('key_id'))  # Convert to integer
    except Exception as e:
        logging.error(f"Error parsing request data: {e}")
        return jsonify({'success': False, 'message': 'Invalid request format'}), 400

    # Log the received data
    app.logger.info(f"Received data: {data}")
    app.logger.info(f"Title: {title}, Login Name: {login_name}, Password: {password}, Site: {site}, Key ID: {key_id}")

    if not all([title, login_name, password, site, key_id]):
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    try:
        with mysql.connection.cursor(DictCursor) as cur:
            # Fetch key_id and encryption key
            app.logger.info(f"Executing query with key_id: {key_id} and user_id: {user_id}")
            cur.execute("SELECT key_id, `key` FROM `keys` WHERE key_id = %s AND Id = %s", (key_id, user_id))
            key_record = cur.fetchone()
            app.logger.info(f"Fetched key record: {key_record}")

            if not key_record:
                logging.warning(f"Key '{key_id}' not found for user {user_id}")
                return jsonify({'success': False, 'message': 'Key not found or unauthorized access'}), 404

            key_id = key_record['key_id']
            encryption_key = key_record['key']

            # Encrypt the password
            fernet = Fernet(encryption_key.encode())
            encrypted_password = fernet.encrypt(password.encode()).decode()

            # Insert the password
            cur.execute("""
                INSERT INTO passwords (user_id, key_id, site, login_name, passwords, title)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, key_id, site, login_name, encrypted_password, title))
            mysql.connection.commit()

            logging.info(f"Password added successfully by user {user_id}")
            return jsonify({'success': True, 'message': 'Container added successfully'}), 200

    except Exception as e:
        mysql.connection.rollback()
        logging.error(f"Error during request processing: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while adding the container.'}), 500




@app.route('/decrypt_password', methods=['POST'])
def decrypt_password():
    # Step 1: Check if user is logged in
    if 'user_id' not in session:
        logger.warning("Unauthorized access attempt to /decrypt_password")
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']

    # Step 2: Validate input fields
    site = request.form.get('site')
    login_name = request.form.get('login_name')
    key_name = request.form.get('key_name')
    title = request.form.get('title')

    if not all([site, login_name, key_name, title]):
        logger.warning(f"Missing fields in request from user {user_id}: site={site}, login_name={login_name}, key_name={key_name}, title={title}")
        return jsonify({'message': 'Missing data in request'}), 400

    cur = mysql.connection.cursor(DictCursor)
    try:
        # Step 3: Fetch the encryption key and ensure ownership
        cur.execute("SELECT key_id, `key` FROM `keys` WHERE Id = %s AND key_name = %s", (user_id, key_name))
        key_record = cur.fetchone()

        if not key_record:
            logger.info(f"Key '{key_name}' not found for user {user_id}")
            return jsonify({'message': 'Key not found'}), 404

        key_id = key_record['key_id']
        encryption_key = key_record['key']

        # Step 4: Fetch the encrypted password
        cur.execute("""
            SELECT `passwords` FROM `passwords` 
            WHERE key_id = %s AND site = %s AND login_name = %s AND title = %s
        """, (key_id, site, login_name, title))
        password_record = cur.fetchone()

        if not password_record:
            logger.info(f"Password not found for user {user_id}: site={site}, login_name={login_name}, title={title}")
            return jsonify({'message': 'Password not found'}), 404

        encrypted_password = password_record['passwords']

        # Step 5: Decrypt the password
        try:
            fernet = Fernet(encryption_key.encode())
            decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
            logger.info(f"Password successfully decrypted for user {user_id}")
            return jsonify({'message': 'Password decrypted successfully', 'password': decrypted_password}), 200
        except InvalidToken:
            logger.error(f"Decryption failed for user {user_id} due to invalid token")
            return jsonify({'message': 'Failed to decrypt the password. Invalid encryption key.'}), 500

    except Exception as e:
        logger.error(f"General error for user {user_id} in /decrypt_password: {e}")
        return jsonify({'message': 'An error occurred while decrypting the password.'}), 500
    finally:
        cur.close()

#UPDATED - TO BE DELETED, GOAL IS TO CONNECT THE FIXED BUTTON TO THE ADD CONTAINER TO BE EFFICIENT    

@app.route('/get_key_id', methods=['POST'])
def get_key_id():
    """
    Retrieve the key_id for a given key_name associated with the logged-in user.
    """
    # Step 1: Ensure the user is logged in
    if 'user_id' not in session:
        logger.warning("Unauthorized access attempt to /get_key_id.")
        return jsonify({'success': False, 'error': 'Unauthorized access. Please log in.'}), 401

    user_id = session['user_id']

    # Step 2: Validate the input
    key_name = request.form.get('key_name')
    if not key_name:
        logger.warning(f"User {user_id} submitted request without 'key_name'.")
        return jsonify({'success': False, 'error': 'Key name is required.'}), 400

    try:
        # Step 3: Retrieve key_id from the database
        with mysql.connection.cursor(DictCursor) as cur:
            query = """
                SELECT key_id 
                FROM keys 
                WHERE key_name = %s AND Id = %s
                LIMIT 1
            """
            cur.execute(query, (key_name, user_id))
            key = cur.fetchone()

            if key:
                logger.info(f"Key ID {key['key_id']} retrieved for user {user_id} and key_name '{key_name}'.")
                return jsonify({'success': True, 'key_id': key['key_id']}), 200
            else:
                logger.info(f"No key found for user {user_id} and key_name '{key_name}'.")
                return jsonify({'success': False, 'error': 'Key not found.'}), 404
    except Exception as e:
        logger.error(f"Error retrieving key ID for user {user_id} with key_name '{key_name}': {e}")
        return jsonify({'success': False, 'error': 'An error occurred while retrieving the key ID.'}), 500

@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    # Step 1: Check if user is logged in
    if 'user_id' not in session:
        logger.warning("Unauthorized access attempt to /delete_password")
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    user_id = session['user_id']

    try:
        with mysql.connection.cursor(DictCursor) as cur:
            # Step 2: Verify ownership of the password
            cur.execute("""
                SELECT passwords.password_id FROM passwords
                JOIN `keys` ON passwords.key_id = keys.key_id
                WHERE passwords.password_id = %s AND keys.Id = %s
                LIMIT 1
            """, (password_id, user_id))
            password = cur.fetchone()

            if not password:
                logger.warning(f"User {user_id} attempted to delete unauthorized or non-existent password_id {password_id}")
                return jsonify({'success': False, 'message': 'Password not found or unauthorized'}), 404

            # Step 3: Delete the password
            cur.execute("DELETE FROM passwords WHERE password_id = %s", (password_id,))
            mysql.connection.commit()

            logger.info(f"User {user_id} successfully deleted password_id {password_id}")
            return jsonify({'success': True, 'message': 'Password deleted successfully'}), 200

    except Exception as e:
        mysql.connection.rollback()
        logger.error(f"Error deleting password_id {password_id} for user_id {user_id}: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while deleting the password. Please try again.'}), 500

@app.route('/get_password/<int:password_id>', methods=['GET'])
def get_password(password_id):
    if 'user_id' not in session:
        logging.warning("Unauthorized access attempt to retrieve password.")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    try:
        with mysql.connection.cursor(DictCursor) as cur:
            logging.debug(f"Fetching password for password_id={password_id}, user_id={user_id}")

            query = """
                SELECT p.password_id, p.key_id, p.passwords, p.site, p.login_name,
                       p.title, k.key_name, k.`key`
                FROM passwords p
                JOIN `keys` k ON p.key_id = k.key_id
                WHERE p.password_id = %s AND k.Id = %s
                LIMIT 1
            """
            cur.execute(query, (password_id, user_id))
            result = cur.fetchone()

            if not result:
                logging.warning(f"No matching record for password_id={password_id}, user_id={user_id}")
                return jsonify({'success': False, 'message': 'Password not found or unauthorized access.'}), 404

            logging.debug(f"Query result: {result}")

            encrypted_password = result['passwords']
            encryption_key = result['key']

            if not encryption_key:
                logging.error(f"Encryption key is null for key_id={result['key_id']}, password_id={password_id}")
                return jsonify({'success': False, 'message': 'Encryption key not found.'}), 500

            try:
                fernet = Fernet(encryption_key.encode())
                decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                logging.info(f"Decrypted password successfully for password_id={password_id}")
            except InvalidToken as e:
                logging.error(f"Invalid decryption token for password_id={password_id}: {e}")
                return jsonify({'success': False, 'message': 'Failed to decrypt the password.'}), 500

            response_data = {
                'password_id': password_id,
                'title': result['title'],
                'login_name': result['login_name'],
                'password': decrypted_password,
                'site': result['site'],
                'key_name': result['key_name'],
                'key_id': result['key_id'],
            }
            logging.debug(f"Response data: {response_data}")
            return jsonify({'success': True, 'data': response_data}), 200

    except Exception as e:
        logging.error(f"Unexpected error retrieving password_id={password_id} for user_id={user_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred while retrieving the password.'}), 500



#NEW UPDATE - UPDATE PASSWORD 2

@app.route('/update_password/<int:password_id>', methods=['POST'])
def update_password(password_id):
    if 'user_id' not in session:
        logging.warning("Unauthorized attempt to update password.")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']

    try:
        # Parse JSON data
        data = request.get_json()
        logging.debug(f"Received data for password update: {data}")

        key_id = data.get('key_id')
        site = data.get('site')
        login_name = data.get('login_name')
        password = data.get('passwords')  # Ensure field names match frontend
        title = data.get('title')

        # Check for required fields
        if not all([key_id, site, login_name, password, title]):
            logging.warning(f"Missing fields in update password request by user {user_id}.")
            return jsonify({'success': False, 'message': 'All fields are required.'}), 400

        with mysql.connection.cursor(DictCursor) as cur:
            # Verify that the new key_id belongs to the user
            cur.execute("""
                SELECT `key` FROM `keys` 
                WHERE key_id = %s AND Id = %s
            """, (key_id, user_id))
            key_record = cur.fetchone()

            if not key_record:
                logging.warning(f"User {user_id} attempted to use invalid key_id {key_id} for password_id {password_id}.")
                return jsonify({'success': False, 'message': 'Encryption key not found or unauthorized.'}), 404

            encryption_key = key_record['key']
            fernet = Fernet(encryption_key.encode())
            encrypted_password = fernet.encrypt(password.encode()).decode()

            # Update the password in the database
            update_query = """
                UPDATE passwords
                SET key_id = %s,
                    site = %s,
                    login_name = %s,
                    passwords = %s,
                    title = %s
                WHERE password_id = %s AND key_id IN (
                    SELECT key_id FROM `keys` WHERE Id = %s
                )
            """
            cur.execute(update_query, (key_id, site, login_name, encrypted_password, title, password_id, user_id))
            mysql.connection.commit()

            if cur.rowcount == 0:
                logging.warning(f"User {user_id} attempted to update non-existent or unauthorized password_id {password_id}.")
                return jsonify({'success': False, 'message': 'Password not found or unauthorized.'}), 404

            logging.info(f"Password_id {password_id} updated successfully by user {user_id}.")
            return jsonify({'success': True, 'message': 'Password updated successfully.'}), 200

    except Exception as e:
        mysql.connection.rollback()
        logging.error(f"Error updating password_id {password_id} for user_id {user_id}: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while updating the password.'}), 500


@app.route('/delete_key/<int:key_id>', methods=['DELETE'])
def delete_key(key_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Ensure the key belongs to the logged-in user
        cur.execute("SELECT key_id FROM `keys` WHERE key_id = %s AND id = %s", (key_id, user_id))
        key = cur.fetchone()

        if not key:
            return jsonify({'success': False, 'message': 'Key not found or unauthorized'}), 404

        cur.execute("""
            DELETE p 
            FROM passwords p
            JOIN `keys` k ON p.key_id = k.key_id
            WHERE p.key_id = %s AND k.id = %s
        """, (key_id, user_id))

        # Delete the key itself
        cur.execute("DELETE FROM `keys` WHERE key_id = %s AND id = %s", (key_id, user_id))

        # Delete the key itself
        cur.execute("DELETE FROM `keys` WHERE key_id = %s", (key_id,))

        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'Key and associated data deleted successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error deleting key with key_id={key_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while deleting the key. Please try again.'}), 500
    finally:
        cur.close()
        
#SETTINGS ROUTE
#update email route
@app.route('/change_email', methods=['POST'])
def change_email():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    new_email = request.form['email']
    user_id = session['user_id']

    # Check if the new email is already in use
    cur = mysql.connection.cursor(DictCursor)
    cur.execute("SELECT Id FROM accounts WHERE email = %s", (new_email,))
    existing_user = cur.fetchone()
    if existing_user:
        cur.close()
        return jsonify({'message': 'Email is already in use. Please use a different email address.'}), 400

    # Generate a new email verification token
    email_verification_token = str(uuid.uuid4())

    # Update the user's record with new_email and email_verification_token
    try:
        cur.execute("""
            UPDATE accounts
            SET new_email = %s, email_verification_token = %s
            WHERE Id = %s
        """, (new_email, email_verification_token, user_id))
        mysql.connection.commit()
    except Exception as e:
        print(f"Error updating email: {e}")
        return jsonify({'message': 'An error occurred while updating the email.'}), 500
    finally:
        cur.close()

    # Send a verification email to the new email address
    verification_link = url_for('verify_new_email', token=email_verification_token, _external=True)
    subject = "Email Verification for Email Change"
    message = f"""
    <p>Hi,</p>
    <p>You have requested to change your email address. Please click the link below to verify your new email address:</p>
    <p><a href="{verification_link}">{verification_link}</a></p>
    <p>If you did not request this change, please ignore this email.</p>
    <p>Best regards,<br>Kryptos***</p>
    """
    try:
        send_email(new_email, subject, message)
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return jsonify({'message': 'Failed to send verification email. Please try again later.'}), 500

    return jsonify({'message': 'A verification email has been sent to your new email address. Please verify to complete the email change.'}), 200

#verify new email
@app.route('/verify_new_email/<token>', methods=['GET'])
def verify_new_email(token):
    cur = mysql.connection.cursor(DictCursor)
    try:
        # Find the user with the matching verification token
        cur.execute("SELECT Id, new_email FROM accounts WHERE email_verification_token = %s", (token,))
        user = cur.fetchone()

        if user:
            # Update the email and clear temporary fields
            cur.execute("""
                UPDATE accounts
                SET email = %s, new_email = NULL, email_verification_token = NULL
                WHERE Id = %s
            """, (user['new_email'], user['Id']))
            mysql.connection.commit()
            flash("Your email address has been updated successfully.", "success")
        else:
            flash("Invalid or expired verification link.", "error")
    except Exception as e:
        print(f"Error verifying new email: {e}")
        flash("An error occurred during email verification.", "error")
    finally:
        cur.close()
    return redirect(url_for('home'))

#Update Username Route
@app.route('/change_username', methods=['POST'])
def change_username():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    new_username = request.form['username']
    user_id = session['user_id']

    # Input validation (optional)
    if not new_username:
        return jsonify({'message': 'Username cannot be empty.'}), 400

    try:
        cur = mysql.connection.cursor(DictCursor)

        # Check if the new username already exists
        cur.execute("SELECT Id FROM accounts WHERE username = %s", (new_username,))
        existing_user = cur.fetchone()

        if existing_user:
            cur.close()
            return jsonify({'message': 'Username already exists. Please choose a different username.'}), 400

        # Update the username
        cur.execute("UPDATE accounts SET username = %s WHERE Id = %s", (new_username, user_id))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Username updated successfully'}), 200

    except Exception as e:
        print(f"Error updating username: {e}")
        return jsonify({'message': 'An error occurred while updating the username.'}), 500

#Update master password route
@app.route('/change_master_password', methods=['POST'])
def change_master_password():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    current_master_password = request.form.get('current_master_password')
    new_master_password = request.form.get('new_master_password')
    confirm_master_password = request.form.get('confirm_master_password')

    if new_master_password != confirm_master_password:
        return jsonify({'message': 'New passwords do not match'}), 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Fetch the current master password hash from the database
        cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
        account = cur.fetchone()

        if not account or not ph.verify(account['master_pass'], current_master_password):
            return jsonify({'message': 'Current master password is incorrect'}), 403

        # Hash the new master password
        hashed_new_master_pass = ph.hash(new_master_password)

        # Update the master password in the database
        cur.execute("UPDATE accounts SET master_pass = %s WHERE Id = %s", (hashed_new_master_pass, user_id))
        mysql.connection.commit()

        return jsonify({'message': 'Master password updated successfully'})
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error updating master password: {e}")
        return jsonify({'message': 'Failed to update master password', 'error': str(e)}), 500
    finally:
        cur.close()
        
#update_security_question
@app.route('/update_security_question', methods=['POST'])
def update_security_question():
    if 'user_id' not in session:
        return jsonify({'message': 'User not logged in'}), 401

    user_id = session['user_id']
    current_master_password = request.form['current_master_password']
    new_security_question = request.form['new_security_question']
    new_security_answer = request.form['new_security_answer']

    # Input validation
    if not all([current_master_password, new_security_question, new_security_answer]):
        return jsonify({'message': 'All fields are required.'}), 400

    try:
        # Fetch the user's current master password hash
        cur = mysql.connection.cursor(DictCursor)
        cur.execute("SELECT master_pass FROM accounts WHERE Id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if not user:
            return jsonify({'message': 'User not found.'}), 404

        # Verify the current master password
        try:
            ph.verify(user['master_pass'], current_master_password)
        except exceptions.VerifyMismatchError:
            return jsonify({'message': 'Incorrect master password.'}), 403

        # Hash the new security answer
        hashed_security_answer = ph.hash(new_security_answer)

        # Update the security question and answer in the database
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE accounts
            SET security_question = %s, security_answer = %s
            WHERE Id = %s
        """, (new_security_question, hashed_security_answer, user_id))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Security question and answer updated successfully.'}), 200

    except Exception as e:
        print(f"Error updating security question: {e}")
        return jsonify({'message': 'An error occurred while updating the security question.'}), 500

'''@app.route('/delete_password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor()

    # Delete only if the password belongs to the logged-in user
    query = """
        DELETE passwords FROM passwords
        JOIN `keys` ON passwords.key_id = `keys`.key_id
        WHERE passwords.password_id = %s AND `keys`.id = %s
    """
    cur.execute(query, (password_id, user_id))
    mysql.connection.commit()
    cur.close()

    return jsonify({'success': True})'''

@app.route('/logout')
def logout():
    session.clear()  # Clear the user session
    return redirect(url_for('login'))  # Redirect to home page or login page

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
