# import json  # for JSON file handling and parsing
import os  # for direct file system and environment access
import re  # for regular expressions
import random  # for captcha random numbers
# import string  # for string operations
import logging  # enable logging

import boto3  # for S3 storage
from flask import Flask, request, render_template, jsonify, send_file, escape, redirect, url_for, \
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

from forms import LoginForm, ContactForm  # Flask/Jinja template forms


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


# Internal helpers - return choices list used in HTML select elements
def get_profile_choices(creator):
    image_choices = list_files(BUCKET_PUBLIC, "user", creator.creator_name)
    image_choices.insert(0, "No Image")
    return image_choices


# Internal helpers - persist selected world in the session to improve navigation and remember selected world
def update_session(world):
    session['world_id'] = world.world_id
    session['world_name'] = world.world_name
    session['reduced'] = world.reduced
    session['s3_prefix'] = f"{S3_FOLDER}/world/{world.world_name}"
    session['s3_folder'] = S3_FOLDER


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


# Force user log-in and return to the site index afterwards
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


# Log out user and return to the site index afterwards
@app.route(APP_PREFIX + '/web/logout', methods=['GET'])
def show_logout():
    update_style("main.css")
    logout_user()
    return redirect(url_for('show_index'))


# --------------------------------------------------------------
# Flask HTML views to read and modify the database contents
# --------------------------------------------------------------

# Show information about all major releases
@app.route(APP_PREFIX + '/web/release', methods=['GET'])
def show_release():
    return render_template('release.html')


# Show privacy policy
@app.route(APP_PREFIX + '/web/privacy', methods=['GET'])
def show_privacy():
    return render_template('privacy.html')


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
