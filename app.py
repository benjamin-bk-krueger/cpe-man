import os  # for direct file system and environment access
import re  # for regular expressions
import random  # for captcha random numbers
import string  # for string operations
import logging  # enable logging

import boto3  # for S3 storage
from flask import Flask, request, render_template, send_file, escape, redirect, url_for, \
    session  # most important Flask modules
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, \
    current_user  # to manage user sessions
from flask_mail import Mail, Message  # to send mails
from flask_marshmallow import Marshmallow  # to marshall our objects
from flask_restx import Resource, Api  # to enable the REST API
from flask_sitemap import Sitemap  # to generate sitemap.xml
from flask_sqlalchemy import SQLAlchemy  # object-relational mapper (ORM)
from flask_wtf.csrf import CSRFProtect  # CSRF protection
from werkzeug.security import generate_password_hash, check_password_hash  # for password hashing
from werkzeug.utils import secure_filename  # to prevent path traversal attacks
from logging.handlers import SMTPHandler  # get crashes via mail

from forms import LoginForm, AccountForm, MailCreatorForm, PassCreatorForm, DelCreatorForm, \
    PasswordForm, PasswordResetForm, ContactForm, FileForm, UploadForm  # Flask/Jinja template forms


# the app configuration is done via environmental variables
POSTGRES_URL = os.environ['POSTGRES_URL']  # DB connection data
POSTGRES_USER = os.environ['POSTGRES_USER']
POSTGRES_PW = os.environ['POSTGRES_PW']
POSTGRES_DB = os.environ['POSTGRES_DB']
SECRET_KEY = os.environ['SECRET_KEY']
WWW_SERVER = os.environ['WWW_SERVER']
MAIL_SERVER = os.environ['MAIL_SERVER']  # mail host
MAIL_SENDER = os.environ['MAIL_SENDER']
MAIL_ADMIN = os.environ['MAIL_ADMIN']
MAIL_ENABLE = int(os.environ['MAIL_ENABLE'])
S3_ENDPOINT = os.environ['S3_ENDPOINT']  # where S3 buckets are located
S3_FOLDER = os.environ['S3_FOLDER']
S3_QUOTA = os.environ['S3_QUOTA']
BUCKET_PUBLIC = os.environ['BUCKET_PUBLIC']
BUCKET_PRIVATE = os.environ['BUCKET_PRIVATE']
UPLOAD_FOLDER = os.environ['HOME'] + "/uploads"  # directory for game data
DOWNLOAD_FOLDER = os.environ['HOME'] + "/downloads"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
APP_VERSION = os.environ['APP_VERSION']
APP_PREFIX = os.environ['APP_PREFIX']
LOG_ENABLE = int(os.environ['LOG_ENABLE'])
LOG_FILE = os.environ['LOG_FILE']

# Flask app configuration containing static (css, img) path and template directory
app = Flask(__name__,
            static_url_path=APP_PREFIX + '/static',
            static_folder='static',
            template_folder='templates')


# enable global variables
@app.context_processor
def inject_version_and_prefix():
    return dict(version=APP_VERSION, prefix=APP_PREFIX)


# Enable logging and crashes via mail
if MAIL_ENABLE == 1:
    mail_handler = SMTPHandler(
        mailhost='127.0.0.1',
        fromaddr=MAIL_SENDER,
        toaddrs=[MAIL_ADMIN],
        subject='CPEMan.info: Application Error'
    )
    mail_handler.setLevel(logging.ERROR)
    mail_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))

    if not app.debug:
        app.logger.addHandler(mail_handler)


# Enable CSRF protection for the app
csrf = CSRFProtect(app)

# Limit file uploads to 16MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000

# sitemap.xml configuration
ext = Sitemap(app=app)

# REST API configuration
api = Api(app)

# Marshall configuration
marsh = Marshmallow(app)

# E-Mail configuration
mail = Mail(app)
app.config['MAIL_SERVER'] = MAIL_SERVER

# DB configuration
db = SQLAlchemy()
DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER, pw=POSTGRES_PW, url=POSTGRES_URL,
                                                               db=POSTGRES_DB)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # silence the deprecation warning
db.init_app(app)

# Login Manager configuration
login_manager = LoginManager()
login_manager.login_view = 'show_login'  # show this page if a login is required
login_manager.init_app(app)


# link the Login Manager to the correct user entry
@login_manager.user_loader
def load_user(creator_id):
    # since the creator_id is just the primary key of our user table, use it in the query for the user
    return Creator.query.get(int(creator_id))


# set S3 standard folder
session['s3_folder'] = S3_FOLDER


# --------------------------------------------------------------
# ORM classes
# --------------------------------------------------------------

# ORM model classes, Creator table is used for the Login Manager
# for each REST-enabled element, we add marshmallow schemas
# enable a REST API to modify the database contents
class Creator(UserMixin, db.Model):
    __tablename__ = "creator"
    creator_id = db.Column(db.INTEGER, primary_key=True)
    creator_name = db.Column(db.VARCHAR(100), unique=True)
    creator_mail = db.Column(db.VARCHAR(100), unique=True)
    creator_desc = db.Column(db.VARCHAR(1024))
    creator_pass = db.Column(db.VARCHAR(256))
    creator_img = db.Column(db.VARCHAR(384))
    creator_role = db.Column(db.VARCHAR(20))
    active = db.Column(db.INTEGER, default=0)
    notification = db.Column(db.INTEGER, default=0)
    password_reset = db.Column(db.VARCHAR(100))

    # match the correct row for the Login Manager ID
    def get_id(self):
        return self.creator_id

    def __repr__(self):
        return '<Creator %s>' % self.creator_name


class Invitation(db.Model):
    __tablename__ = "invitation"
    invitation_id = db.Column(db.INTEGER, primary_key=True)
    invitation_code = db.Column(db.VARCHAR(20))
    invitation_role = db.Column(db.VARCHAR(20))
    invitation_forever = db.Column(db.INTEGER, default=0)
    invitation_taken = db.Column(db.INTEGER, default=0)

    def __repr__(self):
        return '<Invitation %s>' % self.invitation_id


# --------------------------------------------------------------
# Internal functions
# --------------------------------------------------------------

# S3 storage helper functions
def upload_file(bucket, object_name, file_name):
    s3_client = boto3.client('s3', endpoint_url=S3_ENDPOINT)
    response = s3_client.upload_file(file_name, bucket, object_name)
    return response


def download_file(bucket, object_name, file_name):
    s3 = boto3.resource('s3', endpoint_url=S3_ENDPOINT)
    s3.Bucket(bucket).download_file(object_name, file_name)
    return file_name


def delete_file(bucket, object_name):
    s3 = boto3.resource('s3', endpoint_url=S3_ENDPOINT)
    s3.Object(bucket, object_name).delete()


def rename_file(bucket, object_name_new, object_name_old):
    s3 = boto3.resource('s3', endpoint_url=S3_ENDPOINT)
    s3.Object(bucket, object_name_new).copy_from(CopySource=f"{bucket}/{object_name_old}")
    s3.Object(bucket, object_name_old).delete()


def list_files(bucket, section_name, folder_name):
    s3 = boto3.client('s3', endpoint_url=S3_ENDPOINT)
    contents = []
    for item in s3.list_objects(Bucket=bucket)['Contents']:
        if item['Key'].startswith(f"{section_name}/{folder_name}") and item['Key'] != f"{section_name}/{folder_name}/":
            contents.append(item['Key'].replace(f"{section_name}/{folder_name}/", ""))
    return contents


def get_size(bucket, path):
    s3 = boto3.resource('s3', endpoint_url=S3_ENDPOINT)
    my_bucket = s3.Bucket(bucket)
    total_size = 0

    for obj in my_bucket.objects.filter(Prefix=path):
        total_size = total_size + obj.size

    return total_size


def get_all_size(bucket):
    s3 = boto3.client('s3', endpoint_url=S3_ENDPOINT)
    top_level_folders = dict()
    for key in s3.list_objects(Bucket=bucket)['Contents']:
        folder = key['Key'].split('/')[0]
        if folder in top_level_folders:
            top_level_folders[folder] += key['Size']
        else:
            top_level_folders[folder] = key['Size']

    return top_level_folders


# URL sanitization
def clean_url(url):
    return re.sub('[^-A-Za-z0-9+&@#/%?=~_|!:,.;()]', '', url)


# Path traversal prevention
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# check if the basic authentication is valid, used for API calls
class AuthChecker:
    @staticmethod
    def check(auth):
        if auth:
            creator_name = auth['username']
            creator_pass = auth['password']
            creator = Creator.query.filter_by(active=1).filter_by(creator_name=creator_name).first()

            if creator and check_password_hash(creator.creator_pass, creator_pass):
                return True
        return False


# Sitemap page
@ext.register_generator
def index():
    # Not needed if you set SITEMAP_INCLUDE_RULES_WITHOUT_PARAMS=True
    yield 'show_index', {}
    yield 'show_creators', {}
    yield 'show_release', {}


# Send an e-mail
def send_mail(recipients, mail_header, mail_body):
    if MAIL_ENABLE == 1:
        msg = Message(mail_header,
                      sender=MAIL_SENDER,
                      recipients=recipients)
        msg.body = mail_body
        mail.send(msg)


def send_massmail(mail_header, mail_body):
    if MAIL_ENABLE == 1:
        creators = Creator.query.filter_by(active=1).order_by(Creator.creator_name.asc())
        recipients = list()
        bcc = list()
        recipients.append(MAIL_SENDER)
        for creator in creators:
            if creator.notification == 1:
                bcc.append(creator.creator_mail)
        msg = Message(mail_header,
                      sender=MAIL_SENDER,
                      recipients=recipients,
                      bcc=bcc)
        msg.body = mail_body
        mail.send(msg)


# Internal logging
def log_entry(operation, parameters=["none"]):
    if LOG_ENABLE == 1:
        logf = open(LOG_FILE, "a")  # append mode
        logf.write("Operation: " + operation + "\n")
        logf.close()
    elif LOG_ENABLE == 2:
        logf = open(LOG_FILE, "a")  # append mode
        logf.write("Operation: " + operation + ", Parameters: " + ', '.join(parameters) + "\n")
        logf.close()


# Internal helpers - return choices list used in HTML select elements
def get_profile_choices(creator):
    image_choices = list_files(BUCKET_PUBLIC, "user", creator.creator_name)
    image_choices.insert(0, "No Image")
    return image_choices


# Internal helpers - style manager
def update_style(style):
    session['style'] = style


# --------------------------------------------------------------
# Flask entry pages
# --------------------------------------------------------------

# Show site index
@app.route(APP_PREFIX + '/web/', methods=['GET'])
def show_index():
    return render_template('index.html')


# Show error page  - for all "hard" crashes a mail is sent to the site admin
@app.route(APP_PREFIX + '/web/error', methods=['GET'])
def show_error():
    return render_template('error.html')


# Force user log-in and return to the site index afterward
@app.route(APP_PREFIX + '/web/logged', methods=['GET'])
@login_required
def show_logged():
    return redirect(url_for('show_index'))


# Show user log-in page
@app.route(APP_PREFIX + '/web/login', methods=['GET', 'POST'])
def show_login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        creator_name = request.form["creator"]
        creator_pass = request.form["password"]
        remember = True if request.form.get('remember') else False
        creator = Creator.query.filter_by(active=1).filter_by(creator_name=creator_name).first()

        if not creator or not check_password_hash(creator.creator_pass, creator_pass):
            return redirect(url_for('show_login'))
        else:
            if creator.creator_role == "admin":
                update_style("main_admin.css")
            else:
                update_style("main.css")

            login_user(creator, remember=remember)
            return redirect(url_for('show_index'))
    else:
        return render_template('login.html', form=form)


# Log out user and return to the site index afterward
@app.route(APP_PREFIX + '/web/logout', methods=['GET'])
def show_logout():
    update_style("main.css")
    logout_user()
    return redirect(url_for('show_index'))


# Show user password reset page
@app.route(APP_PREFIX + '/web/password', methods=['GET', 'POST'])
def show_password():
    form = PasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        if MAIL_ENABLE == 1:
            creator_email = request.form["email"]

            creators = Creator.query.filter_by(active=1).order_by(Creator.creator_name.asc())
            recipients = list()
            for creator in creators:
                if creator.creator_mail == creator_email:
                    random_hash = ''.join(random.sample(string.ascii_letters + string.digits, 32))
                    creator.password_reset = random_hash
                    db.session.commit()

                    recipients.append(creator.creator_mail)
                    msg = Message("Password Reset Link",
                                  sender=MAIL_SENDER,
                                  recipients=recipients
                                  )
                    msg.body = "Reset your password here: " + WWW_SERVER + url_for('show_password_reset',
                                                                                   random_hash=random_hash)
                    mail.send(msg)
        return redirect(url_for('show_index'))
    else:
        return render_template('password.html', form=form)


# Show user password reset page
@app.route(APP_PREFIX + '/web/reset_password/<string:random_hash>', methods=['GET', 'POST'])
def show_password_reset(random_hash):
    form = PasswordResetForm()
    if request.method == 'POST' and form.validate_on_submit():
        creators = Creator.query.filter_by(active=1).order_by(Creator.creator_name.asc())
        for creator in creators:
            if creator.password_reset == random_hash and len(random_hash) > 30:
                creator.creator_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                              salt_length=16)
                creator.password_reset = ""
                db.session.commit()
        return redirect(url_for('show_index'))
    else:
        return render_template('password_reset.html', form=form, random_hash=random_hash)


# --------------------------------------------------------------
# S3 storage pages
# --------------------------------------------------------------

# Show list of all uploaded filed and upload form
@app.route(APP_PREFIX + "/web/storage/<string:section_name>/<string:folder_name>", methods=['GET', 'POST'])
@login_required
def show_storage(section_name, folder_name):
    form = UploadForm()
    form2 = FileForm()

    if section_name == "user" and current_user.is_authenticated and current_user.creator_name == folder_name:
        space_used_in_mb = round((get_size(BUCKET_PUBLIC, f"{section_name}/{folder_name}/") / 1024 / 1024), 2)
        space_used = int(space_used_in_mb / int(S3_QUOTA) * 100)

        if request.method == 'POST' and form.validate_on_submit():
            filename = secure_filename(form.file.data.filename)

            if allowed_file(filename) and space_used < 100:
                local_folder_name = f"{UPLOAD_FOLDER}/{current_user.creator_name}"
                local_file = os.path.join(local_folder_name, filename)
                remote_file = f"{section_name}/{folder_name}/{filename}"
                if not os.path.exists(local_folder_name):
                    os.makedirs(local_folder_name)
                form.file.data.save(local_file)
                upload_file(BUCKET_PUBLIC, remote_file, local_file)
            return redirect(url_for('show_storage', section_name=section_name, folder_name=folder_name))
        else:
            contents = list_files(BUCKET_PUBLIC, section_name, folder_name)
            return render_template('storage.html', section_name=section_name, folder_name=folder_name,
                                   contents=contents, space_used_in_mb=space_used_in_mb, space_used=space_used,
                                   form=form, form2=form2)
    else:
        return render_template('error.html')


# Change a filename
@app.route(APP_PREFIX + "/web/rename/<string:section_name>/<string:folder_name>", methods=['POST'])
@login_required
def do_rename(section_name, folder_name):
    if section_name == "user" and current_user.is_authenticated and current_user.creator_name == folder_name:
        remote_file_new = f"{secure_filename(section_name)}/{secure_filename(folder_name)}/{secure_filename(request.form['filename_new'])}"
        remote_file_old = f"{secure_filename(section_name)}/{secure_filename(folder_name)}/{secure_filename(request.form['filename_old'])}"
        if remote_file_new != remote_file_old and allowed_file(remote_file_new):
            log_entry(__name__, [BUCKET_PUBLIC, remote_file_new, remote_file_old])
            rename_file(BUCKET_PUBLIC, remote_file_new, remote_file_old)

        return redirect(url_for('show_storage', section_name=section_name, folder_name=folder_name))
    else:
        return render_template('error.html')


# Download a specific file from S3 storage
@app.route(APP_PREFIX + "/web/download/<string:section_name>/<string:folder_name>/<string:filename>", methods=['GET'])
@login_required
def do_download(section_name, folder_name, filename):
    if section_name == "user" and current_user.is_authenticated and current_user.creator_name == folder_name:
        local_folder_name = f"{DOWNLOAD_FOLDER}/{current_user.creator_name}"
        local_filename = os.path.join(local_folder_name, secure_filename(filename))
        remote_file = f"{secure_filename(section_name)}/{secure_filename(folder_name)}/{secure_filename(filename)}"

        if not os.path.exists(local_folder_name):
            os.makedirs(local_folder_name)
        output = download_file(BUCKET_PUBLIC, remote_file, local_filename)
        # return send_from_directory(app.config["UPLOAD_FOLDER"], name)
        return send_file(output, as_attachment=True)
    else:
        return render_template('error.html')


# Remove a specific file from S3 storage
@app.route(APP_PREFIX + "/web/delete/<string:section_name>/<string:folder_name>/<string:filename>", methods=['GET'])
@login_required
def do_delete(section_name, folder_name, filename):
    if section_name == "user" and current_user.is_authenticated and current_user.creator_name == folder_name:
        remote_file = f"{secure_filename(section_name)}/{secure_filename(folder_name)}/{secure_filename(filename)}"
        delete_file(BUCKET_PUBLIC, remote_file)
        return redirect(url_for('show_storage', section_name=section_name, folder_name=folder_name))
    else:
        return render_template('error.html')


# --------------------------------------------------------------
# Flask HTML views to read and modify the database contents
# --------------------------------------------------------------

# Show statistics regarding available elements stored in the database and on S3 storage
@app.route(APP_PREFIX + '/web/stats', methods=['GET'])
def show_stats():
    counts = dict()
    counts['creator'] = Creator.query.count()

    bucket_all = get_all_size(BUCKET_PUBLIC)

    return render_template('stats.html', counts=counts, bucket_all=bucket_all)


# Show information about all major releases
@app.route(APP_PREFIX + '/web/release', methods=['GET'])
def show_release():
    return render_template('release.html')


# Show privacy policy
@app.route(APP_PREFIX + '/web/privacy', methods=['GET'])
def show_privacy():
    return render_template('privacy.html')


# Displays an image file stored on S3 storage
@app.route(APP_PREFIX + '/web/image/<string:section_name>/<string:folder_name>/<string:filename>', methods=['GET'])
@login_required
def show_image(section_name, folder_name, filename):
    if section_name == "user" and current_user.is_authenticated and current_user.creator_name == folder_name:
        return render_template('image.html', section_name=secure_filename(section_name),
                               folder_name=secure_filename(folder_name), filename=secure_filename(filename))
    else:
        return render_template('error.html')


# Displays a form to send a message to the site admin - implements a simple captcha as well
@app.route(APP_PREFIX + '/web/contact', methods=['GET', 'POST'])
def show_contact():
    form = ContactForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            contact_name = escape(request.form["contact_name"])
            email = escape(request.form["email"])
            message = escape(request.form["message"])

            send_mail([MAIL_ADMIN], f"{contact_name} - {email}",
                      f"{message}")

            return redirect(url_for('show_index'))
        else:
            form.contact_name.default = escape(request.form["contact_name"])
            form.email.default = escape(request.form["email"])
            form.message.default = escape(request.form["message"])

            random1 = random.randint(1, 10)
            random2 = random.randint(1, 10)
            check_captcha = random1 + random2

            form.check_captcha.default = check_captcha
            form.process()

            return render_template('contact.html', form=form, random1=random1, random2=random2,
                                   check_captcha=check_captcha)
    else:
        random1 = random.randint(1, 10)
        random2 = random.randint(1, 10)
        check_captcha = random1 + random2

        form.check_captcha.default = check_captcha
        form.process()

        return render_template('contact.html', form=form, random1=random1, random2=random2, check_captcha=check_captcha)


# Displays all available creators
@app.route(APP_PREFIX + '/web/creators', methods=['GET'])
def show_creators():
    if current_user.is_authenticated and current_user.creator_id and current_user.creator_role == "admin":
        creators = Creator.query.order_by(Creator.creator_name.asc())
    else:
        creators = Creator.query.filter_by(active=1).order_by(Creator.creator_name.asc())
    return render_template('creator.html', creators=creators)


# Shows information about a specific creator
@app.route(APP_PREFIX + '/web/creator/<int:creator_id>', methods=['GET'])
def show_creator(creator_id):
    if current_user.is_authenticated and current_user.creator_id and current_user.creator_role == "admin":
        creator = Creator.query.filter_by(creator_id=creator_id).first()
    else:
        creator = Creator.query.filter_by(active=1).filter_by(creator_id=creator_id).first()

    if creator:
        s3_prefix = f"{S3_FOLDER}/user/{creator.creator_name}"

        return render_template('creator_detail.html', creator=creator, s3_prefix=s3_prefix)
    else:
        return render_template('error.html', error_message="That creator does not exist.")


# Displays a form to create a new user (aka creator)
@app.route(APP_PREFIX + '/web/new_creator', methods=['GET', 'POST'])
def show_new_creator():
    form = AccountForm()
    if request.method == 'POST' and form.validate_on_submit():
        code = request.form["invitation"]
        invitation = Invitation.query.filter_by(invitation_code=code).first()

        existing_creator_1 = Creator.query.filter_by(creator_mail=escape(request.form["email"])).first()
        existing_creator_2 = Creator.query.filter_by(creator_name=escape(request.form["creator"])).first()

        if existing_creator_1 is None and existing_creator_2 is None:
            if invitation and (invitation.invitation_forever == 1 or invitation.invitation_taken == 0):
                creator = Creator()
                creator.creator_name = escape(request.form["creator"])
                creator.creator_mail = escape(request.form["email"])
                creator.creator_desc = ""
                creator.creator_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                              salt_length=16)
                creator.creator_role = invitation.invitation_role
                creator.creator_img = ""
                creator.active = 1
                db.session.add(creator)
                db.session.commit()

                invitation.invitation_taken = 1
                db.session.commit()

                send_mail([MAIL_ADMIN], f"{creator.creator_name} - Registration complete",
                          "A new user has registered using an invitation code. No action necessary.")
            else:
                creator = Creator()
                creator.creator_name = escape(request.form["creator"])
                creator.creator_mail = escape(request.form["email"])
                creator.creator_desc = ""
                creator.creator_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                              salt_length=16)
                creator.creator_role = "user"
                creator.creator_img = ""
                creator.active = 0
                db.session.add(creator)
                db.session.commit()

                send_mail([MAIL_ADMIN], f"{creator.creator_name} - Approval required",
                          "A new user has registered, please approve registration.")

                send_mail([creator.creator_mail], f"{creator.creator_name} - Registration pending",
                          "Your registration needs to be approved. This should not take too long.")
            return redirect(url_for('show_creators'))
        else:
            return render_template('account.html', form=form)
    else:
        return render_template('account.html', form=form)


# Displays various forms to change the currently logged-in user
@app.route(APP_PREFIX + '/web/my_creator', methods=['GET'])
@login_required
def show_my_creator():
    form1 = MailCreatorForm()
    form2 = PassCreatorForm()
    form3 = DelCreatorForm()
    creator = Creator.query.filter_by(creator_id=current_user.creator_id).first()

    form1.email.default = creator.creator_mail
    form1.description.default = creator.creator_desc
    form1.image.choices = get_profile_choices(creator)
    form1.image.default = creator.creator_img
    form1.notification.default = creator.notification
    form1.process()
    return render_template('account_detail.html', creator=creator, form1=form1, form2=form2, form3=form3)


# Post a change of user data or display error message if some data was not entered correctly
@app.route(APP_PREFIX + '/web/my_mail_creator', methods=['POST'])
@login_required
def show_my_mail_creator():
    form1 = MailCreatorForm()
    form2 = PassCreatorForm()
    form3 = DelCreatorForm()
    creator = Creator.query.filter_by(creator_id=current_user.creator_id).first()

    if creator:
        if form1.validate_on_submit():
            old_mail = creator.creator_mail
            creator.creator_mail = escape(request.form["email"])
            creator.creator_desc = request.form["description"]
            creator.creator_img = escape(request.form["image"])
            creator.notification = 1 if request.form.get('notification') else 0
            db.session.commit()

            send_mail([creator.creator_mail], "Notification: E-Mail changed",
                      f"You have changed you e-mail address from {old_mail} to {creator.creator_mail}.")

            return redirect(url_for('show_my_creator'))
        else:
            form1.email.default = creator.creator_mail
            form1.description.default = creator.creator_desc
            form1.image.choices = get_profile_choices(creator)
            form1.image.default = creator.creator_img
            form1.notification.default = creator.notification
            form1.process()
            return render_template('account_detail.html', creator=creator, form1=form1, form2=form2, form3=form3)
    else:
        return render_template('error.html', error_message="That creator does not exist.")


# Post a user's password change or display error message if some data was not entered correctly
@app.route(APP_PREFIX + '/web/my_pass_creator', methods=['POST'])
@login_required
def show_my_pass_creator():
    form1 = MailCreatorForm()
    form2 = PassCreatorForm()
    form3 = DelCreatorForm()
    creator = Creator.query.filter_by(creator_id=current_user.creator_id).first()

    if creator:
        if form2.validate_on_submit():
            creator.creator_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                          salt_length=16)
            db.session.commit()
            return redirect(url_for('show_my_creator'))
        else:
            form1.email.default = creator.creator_mail
            form1.description.default = creator.creator_desc
            form1.image.choices = get_profile_choices(creator)
            form1.image.default = creator.creator_img
            form1.process()
            return render_template('account_detail.html', creator=creator, form1=form1, form2=form2, form3=form3)
    else:
        return render_template('error.html', error_message="That creator does not exist.")


# Delete a user and return to the site index afterward
@app.route(APP_PREFIX + '/web/my_del_creator', methods=['POST'])
@login_required
def show_my_del_creator():
    form1 = MailCreatorForm()
    form2 = PassCreatorForm()
    form3 = DelCreatorForm()
    creator = Creator.query.filter_by(creator_id=current_user.creator_id).first()

    if creator:
        if form3.validate_on_submit():
            Creator.query.filter_by(creator_id=current_user.creator_id).delete()
            db.session.commit()
            logout_user()
            return redirect(url_for('show_index'))
        else:
            form1.email.default = creator.creator_mail
            form1.description.default = creator.creator_desc
            form1.image.choices = get_profile_choices(creator)
            form1.image.default = creator.creator_img
            form1.process()
            return render_template('account_detail.html', creator=creator, form1=form1, form2=form2, form3=form3)
    else:
        return render_template('error.html', error_message="That creator does not exist.")


# Approve a user's registration
@app.route(APP_PREFIX + '/web/approve_creator/<int:creator_id>', methods=['GET'])
@login_required
def show_approve_creator(creator_id):
    if current_user.is_authenticated and current_user.creator_id and current_user.creator_role == "admin":
        creator = Creator.query.filter_by(creator_id=creator_id).first()
        creator.active = 1
        db.session.commit()

        send_mail([creator.creator_mail], f"{creator.creator_name} - Registration complete",
                  "Your registration has been approved. You can use your login now.")

        return redirect(url_for('show_creators'))
    else:
        return render_template('error.html')
