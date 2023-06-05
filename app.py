import os  # for direct file system and environment access
import re  # for regular expressions
import random  # for captcha random numbers
import string  # for string operations
import logging  # enable logging
import datetime  # for date conversion

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

from forms import LoginForm, AccountForm, MailStudentForm, PassStudentForm, DelStudentForm, \
    PasswordForm, PasswordResetForm, ContactForm, FileForm, UploadForm, \
    OrganizationForm, CertificationForm  # Flask/Jinja template forms


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
S3_QUOTA = os.environ['S3_QUOTA']
S3_BUCKET = os.environ['S3_BUCKET']
S3_GLOBAL = os.environ['S3_GLOBAL']
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
api = Api(app, decorators=[csrf.exempt])

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
def load_user(student_id):
    # since the student_id is just the primary key of our user table, use it in the query for the user
    return Student.query.get(int(student_id))


# --------------------------------------------------------------
# ORM classes
# --------------------------------------------------------------

# ORM model classes, Student table is used for the Login Manager
# for each REST-enabled element, we add marshmallow schemas
# enable a REST API to modify the database contents
class Student(UserMixin, db.Model):
    __tablename__ = "student"
    student_id = db.Column(db.INTEGER, primary_key=True)
    student_name = db.Column(db.VARCHAR(100), unique=True)
    student_mail = db.Column(db.VARCHAR(100), unique=True)
    student_desc = db.Column(db.VARCHAR(1024))
    student_pass = db.Column(db.VARCHAR(256))
    student_img = db.Column(db.VARCHAR(384))
    student_role = db.Column(db.VARCHAR(20))
    active = db.Column(db.INTEGER, default=0)
    notification = db.Column(db.INTEGER, default=0)
    password_reset = db.Column(db.VARCHAR(100))

    # match the correct row for the Login Manager ID
    def get_id(self):
        return self.student_id

    def __repr__(self):
        return '<Student %s>' % self.student_name


class Invitation(db.Model):
    __tablename__ = "invitation"
    invitation_id = db.Column(db.INTEGER, primary_key=True)
    invitation_code = db.Column(db.VARCHAR(20), unique=True)
    invitation_role = db.Column(db.VARCHAR(20))
    invitation_forever = db.Column(db.INTEGER, default=0)
    invitation_taken = db.Column(db.INTEGER, default=0)

    def __repr__(self):
        return '<Invitation %s>' % self.invitation_id


class Organization(db.Model):
    __tablename__ = "organization"
    organization_id = db.Column(db.INTEGER, primary_key=True)
    student_id = db.Column(db.INTEGER, db.ForeignKey("student.student_id"))
    organization_name = db.Column(db.VARCHAR(100), unique=True)
    organization_desc = db.Column(db.VARCHAR(1024))
    organization_url = db.Column(db.VARCHAR(256))
    organization_img = db.Column(db.VARCHAR(384))

    def __repr__(self):
        return '<Organization %s>' % self.organization_name


class OrganizationSchema(marsh.Schema):
    class Meta:
        fields = ("organization_id", "student_id", "organization_name", "organization_desc", "organization_url", "organization_img")
        model = Organization


organization_schema = OrganizationSchema()
organizations_schema = OrganizationSchema(many=True)


class OrganizationListResource(Resource):
    @staticmethod
    def get():
        if AuthChecker().check(request.authorization, ["student", "admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            organizations = Organization.query.filter_by(student_id=student.student_id)
            return organizations_schema.dump(organizations)
        else:
            return jsonify({'error': 'wrong credentials or permissions'})

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, ["admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('organization_name', 'organization_desc', 'organization_url', 'organization_img')):
                new_organization = Organization(
                    student_id=student.student_id,
                    organization_name=escape(request.json['organization_name']),
                    organization_desc=request.json['organization_desc'],
                    organization_url=clean_url(request.json['organization_url']),
                    organization_img=clean_url(request.json['organization_img'])
                )
                db.session.add(new_organization)
                db.session.commit()
                return organization_schema.dump(new_organization)
            else:
                return jsonify({'error': 'wrong JSON format'})
        else:
            return jsonify({'error': 'wrong credentials or permissions'})


class OrganizationResource(Resource):
    @staticmethod
    def get(organization_name):
        if AuthChecker().check(request.authorization, ["student", "admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            organization = Organization.query.filter_by(student_id=student.student_id).\
                filter_by(organization_name=organization_name).first()
            return organization_schema.dump(organization)
        else:
            return jsonify({'error': 'wrong credentials or permissions'})

    @staticmethod
    def patch(organization_name):
        if AuthChecker().check(request.authorization, ["admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            organization = Organization.query.filter_by(student_id=student.student_id).\
                filter_by(organization_name=organization_name).first()
            if all(s in request.json for s in ('organization_name', 'organization_desc', 'organization_url', 'organization_img')):
                organization.organization_name = escape(request.json['organization_name'])
                organization.organization_desc = request.json['organization_desc']
                organization.organization_url = clean_url(request.json['organization_url'])
                organization.organization_img = clean_url(request.json['organization_img'])
                db.session.commit()
                return organization_schema.dump(organization)
            else:
                return jsonify({'error': 'wrong JSON format'})
        else:
            return jsonify({'error': 'wrong credentials or permissions'})

    @staticmethod
    def delete(organization_name):
        if AuthChecker().check(request.authorization, ["admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            organization = Organization.query.filter_by(student_id=student.student_id).\
                filter_by(organization_name=organization_name).first()
            db.session.delete(organization)
            db.session.commit()
            return '', 204
        else:
            return jsonify({'error': 'wrong credentials or permissions'})


api.add_resource(OrganizationListResource, APP_PREFIX + '/api/organizations')
api.add_resource(OrganizationResource, APP_PREFIX + '/api/organizations/<string:organization_name>')


class Certification(db.Model):
    __tablename__ = "certification"
    certification_id = db.Column(db.INTEGER, primary_key=True)
    student_id = db.Column(db.INTEGER, db.ForeignKey("student.student_id"))
    organization_id = db.Column(db.INTEGER, db.ForeignKey("organization.organization_id"))
    certification_name = db.Column(db.VARCHAR(100))
    certification_desc = db.Column(db.VARCHAR(1024))
    certification_url = db.Column(db.VARCHAR(256))
    certification_img = db.Column(db.VARCHAR(384))
    cycle_length = db.Column(db.INTEGER, default=3)
    requirement_year = db.Column(db.INTEGER, default=20)
    requirement_full = db.Column(db.INTEGER, default=90)

    def __repr__(self):
        return '<Certification %s>' % self.certification_name


class CertificationSchema(marsh.Schema):
    class Meta:
        fields = ("certification_id", "student_id", "organization_id", "certification_name", "certification_desc", "certification_url", "certification_img", "cycle_length", "requirement_year", "requirement_full")
        model = Certification


certification_schema = CertificationSchema()
certifications_schema = CertificationSchema(many=True)


class CertificationListResource(Resource):
    @staticmethod
    def get():
        if AuthChecker().check(request.authorization, ["student","admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            certifications = Certification.query.filter_by(student_id=student.student_id)
            return certifications_schema.dump(certifications)
        else:
            return jsonify({'error': 'wrong credentials or permissions'})

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, ["admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('organization_id', 'certification_name', 'certification_desc', 'certification_url', 'certification_img', 'cycle_length', 'requirement_year', 'requirement_full')):
                new_certification = Certification(
                    student_id=student.student_id,
                    organization_id=int(escape(request.json['organization_id'])),
                    certification_name=escape(request.json['certification_name']),
                    certification_desc=request.json['certification_desc'],
                    certification_url=clean_url(request.json['certification_url']),
                    certification_img=clean_url(request.json['certification_img']),
                    cycle_length=int(escape(request.json['cycle_length'])),
                    requirement_year=int(escape(request.json['requirement_year'])),
                    requirement_full=int(escape(request.json['requirement_full']))
                )
                db.session.add(new_certification)
                db.session.commit()
                return certification_schema.dump(new_certification)
            else:
                return jsonify({'error': 'wrong JSON format'})
        else:
            return jsonify({'error': 'wrong credentials or permissions'})


class CertificationResource(Resource):
    @staticmethod
    def get(certification_name):
        if AuthChecker().check(request.authorization, ["student","admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            certification = Certification.query.filter_by(student_id=student.student_id).\
                filter_by(certification_name=certification_name).first()
            return certification_schema.dump(certification)
        else:
            return jsonify({'error': 'wrong credentials or permissions'})

    @staticmethod
    def patch(certification_name):
        if AuthChecker().check(request.authorization, ["admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            certification = Certification.query.filter_by(student_id=student.student_id).\
                filter_by(certification_name=certification_name).first()
            if all(s in request.json for s in ('organization_id', 'certification_name', 'certification_desc', 'certification_url', 'certification_img', 'cycle_length', 'requirement_year', 'requirement_full')):
                certification.organization_id = int(escape(request.json['organization_id'])),
                certification.certification_name = escape(request.json['certification_name']),
                certification.certification_desc = request.json['certification_desc'],
                certification.certification_url = clean_url(request.json['certification_url']),
                certification.certification_img = clean_url(request.json['certification_img']),
                certification.cycle_length = int(escape(request.json['cycle_length'])),
                certification.requirement_year = int(escape(request.json['requirement_year'])),
                certification.requirement_full = int(escape(request.json['requirement_full']))
                db.session.commit()
                return certification_schema.dump(certification)
            else:
                return jsonify({'error': 'wrong JSON format'})
        else:
            return jsonify({'error': 'wrong credentials or permissions'})

    @staticmethod
    def delete(certification_name):
        if AuthChecker().check(request.authorization, ["admin"]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            certification = Certification.query.filter_by(student_id=student.student_id).\
                filter_by(certification_name=certification_name).first()
            db.session.delete(certification)
            db.session.commit()
            return '', 204
        else:
            return jsonify({'error': 'wrong credentials or permissions'})


api.add_resource(CertificationListResource, APP_PREFIX + '/api/certifications')
api.add_resource(CertificationResource, APP_PREFIX + '/api/certifications/<string:certification_name>')


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


def list_files(bucket, folder_name):
    s3 = boto3.client('s3', endpoint_url=S3_ENDPOINT)
    contents = []
    for item in s3.list_objects(Bucket=bucket)['Contents']:
        if item['Key'].startswith(f"{folder_name}") and item['Key'] != f"{folder_name}/":
            contents.append(item['Key'].replace(f"{folder_name}/", ""))
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
    def check(auth, role):
        if auth:
            student_name = auth['username']
            student_pass = auth['password']
            student = Student.query.filter_by(active=1).filter_by(student_name=student_name).first()

            if student and check_password_hash(student.student_pass, student_pass) and student.student_role in role:
                return True
        return False


# Sitemap page
@ext.register_generator
def index():
    # Not needed if you set SITEMAP_INCLUDE_RULES_WITHOUT_PARAMS=True
    yield 'show_index', {}
    yield 'show_release', {}
    yield 'show_privacy', {}
    yield 'show_organizations', {}
    yield 'show_certifications', {}
    yield 'show_stats', {}


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
        students = Student.query.filter_by(active=1).order_by(Student.student_name.asc())
        recipients = list()
        bcc = list()
        recipients.append(MAIL_SENDER)
        for student in students:
            if student.notification == 1:
                bcc.append(student.student_mail)
        msg = Message(mail_header,
                      sender=MAIL_SENDER,
                      recipients=recipients,
                      bcc=bcc)
        msg.body = mail_body
        mail.send(msg)


# Internal logging
def log_entry(operation, parameters=None):
    if parameters is None:
        parameters = ["none"]
    if LOG_ENABLE == 1:
        logf = open(LOG_FILE, "a")  # append mode
        logf.write("Operation: " + operation + "\n")
        logf.close()
    elif LOG_ENABLE == 2:
        logf = open(LOG_FILE, "a")  # append mode
        logf.write("Operation: " + operation + ", Parameters: " + ', '.join(parameters) + "\n")
        logf.close()


# Internal helpers - return choices list used in HTML select elements
def get_file_choices(folder):
    image_choices = list_files(S3_BUCKET, folder)
    image_choices.insert(0, "No Image")
    return image_choices


def get_organization_choices(organizations):
    organizations_choices = list()
    for organization in organizations:
        organizations_choices.append((organization.organization_id, organization.organization_name))
    return organizations_choices


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
        student_name = request.form["student"]
        student_pass = request.form["password"]
        remember = True if request.form.get('remember') else False
        student = Student.query.filter_by(active=1).filter_by(student_name=student_name).first()

        if not student or not check_password_hash(student.student_pass, student_pass):
            return redirect(url_for('show_login'))
        else:
            if student.student_role == "admin":
                update_style("main_admin.css")
            else:
                update_style("main.css")

            login_user(student, remember=remember)
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
            student_email = request.form["email"]

            students = Student.query.filter_by(active=1).order_by(Student.student_name.asc())
            recipients = list()
            for student in students:
                if student.student_mail == student_email:
                    random_hash = ''.join(random.sample(string.ascii_letters + string.digits, 32))
                    student.password_reset = random_hash
                    db.session.commit()

                    recipients.append(student.student_mail)
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
        students = Student.query.filter_by(active=1).order_by(Student.student_name.asc())
        for student in students:
            if student.password_reset == random_hash and len(random_hash) > 30:
                student.student_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                              salt_length=16)
                student.password_reset = ""
                db.session.commit()
        return redirect(url_for('show_index'))
    else:
        return render_template('password_reset.html', form=form, random_hash=random_hash)


# --------------------------------------------------------------
# S3 storage pages
# --------------------------------------------------------------

# Show list of all uploaded filed and upload form
@app.route(APP_PREFIX + "/web/storage", methods=['GET', 'POST'])
@login_required
def show_storage():
    form = UploadForm()
    form2 = FileForm()
    filename_new = form2.filename_new.data if form2.filename_new else "none"
    filename_old = form2.filename_old.data if form2.filename_old else "none"
    s3_folder = S3_GLOBAL if current_user.student_role == "admin" else current_user.student_name

    space_used_in_mb = round((get_size(S3_BUCKET, f"{s3_folder}/") / 1024 / 1024), 2)
    space_used = int(space_used_in_mb / int(S3_QUOTA) * 100)

    if request.method == 'POST' and form.validate_on_submit():
        filename = secure_filename(form.file.data.filename)

        if allowed_file(filename) and space_used < 100:
            local_folder_name = f"{UPLOAD_FOLDER}/{s3_folder}"
            local_file = os.path.join(local_folder_name, filename)
            remote_file = f"{s3_folder}/{filename}"
            if not os.path.exists(local_folder_name):
                os.makedirs(local_folder_name)
            form.file.data.save(local_file)
            upload_file(S3_BUCKET, remote_file, local_file)
        return redirect(url_for('show_storage'))
    else:
        contents = list_files(S3_BUCKET, s3_folder)
        return render_template('storage.html',
                               contents=contents, space_used_in_mb=space_used_in_mb, space_used=space_used,
                               form=form, form2=form2, filename_new=filename_new, filename_old=filename_old)


# Change a filename
@app.route(APP_PREFIX + "/web/rename", methods=['POST'])
@login_required
def do_rename():
    form = UploadForm()
    form2 = FileForm()
    filename_new = form2.filename_new.data if form2.filename_new else "none"
    filename_old = form2.filename_old.data if form2.filename_old else "none"
    s3_folder = S3_GLOBAL if current_user.student_role == "admin" else current_user.student_name

    space_used_in_mb = round((get_size(S3_BUCKET, f"{s3_folder}/") / 1024 / 1024), 2)
    space_used = int(space_used_in_mb / int(S3_QUOTA) * 100)

    if request.method == 'POST' and form2.validate_on_submit():
        remote_file_new = f"{secure_filename(s3_folder)}/{secure_filename(request.form['filename_new'])}"
        remote_file_old = f"{secure_filename(s3_folder)}/{secure_filename(request.form['filename_old'])}"
        if remote_file_new != remote_file_old and allowed_file(remote_file_new):
            log_entry(__name__, [S3_BUCKET, remote_file_new, remote_file_old])
            rename_file(S3_BUCKET, remote_file_new, remote_file_old)

        return redirect(url_for('show_storage'))
    else:
        contents = list_files(S3_BUCKET, s3_folder)
        return render_template('storage.html',
                               contents=contents, space_used_in_mb=space_used_in_mb, space_used=space_used,
                               form=form, form2=form2, filename_new=filename_new, filename_old=filename_old)


# Download a specific file from S3 storage
@app.route(APP_PREFIX + "/web/download/<string:filename>", methods=['GET'])
@login_required
def do_download(filename):
    s3_folder = S3_GLOBAL if current_user.student_role == "admin" else current_user.student_name
    local_folder_name = f"{DOWNLOAD_FOLDER}/{s3_folder}"
    local_filename = os.path.join(local_folder_name, secure_filename(filename))
    remote_file = f"{secure_filename(s3_folder)}/{secure_filename(filename)}"

    if not os.path.exists(local_folder_name):
        os.makedirs(local_folder_name)
    output = download_file(S3_BUCKET, remote_file, local_filename)
    # return send_from_directory(app.config["UPLOAD_FOLDER"], name)
    return send_file(output, as_attachment=True)


# Download a specific file from S3 storage - Global and User area
@app.route(APP_PREFIX + "/web/display/<string:username>/<string:filename>", methods=['GET'])
def do_display(username, filename):
    if username == S3_GLOBAL:
        s3_folder = username
    else:
        student = Student.query.filter_by(student_name=username).first()
        if student and (student.student_img == filename or current_user.student_name == username):
            s3_folder = student.student_name
        else:
            return render_template('error.html', error_message="You are not allowed to view that file.")

    local_folder_name = f"{DOWNLOAD_FOLDER}/{s3_folder}"
    local_filename = os.path.join(local_folder_name, secure_filename(filename))
    remote_file = f"{secure_filename(s3_folder)}/{secure_filename(filename)}"

    if not os.path.exists(local_folder_name):
        os.makedirs(local_folder_name)
    output = download_file(S3_BUCKET, remote_file, local_filename)
    # return send_from_directory(app.config["UPLOAD_FOLDER"], name)
    return send_file(output, as_attachment=False)


# Remove a specific file from S3 storage
@app.route(APP_PREFIX + "/web/delete/<string:filename>", methods=['GET'])
@login_required
def do_delete(filename):
    s3_folder = S3_GLOBAL if current_user.student_role == "admin" else current_user.student_name
    remote_file = f"{secure_filename(s3_folder)}/{secure_filename(filename)}"
    delete_file(S3_BUCKET, remote_file)
    return redirect(url_for('show_storage'))


# --------------------------------------------------------------
# Flask HTML views to read and modify the database contents
# --------------------------------------------------------------

# Show statistics regarding available elements stored in the database and on S3 storage
@app.route(APP_PREFIX + '/web/stats', methods=['GET'])
def show_stats():
    counts = dict()
    counts['student'] = Student.query.count()
    counts['organization'] = Organization.query.count()
    counts['certification'] = Certification.query.count()

    if current_user.is_authenticated and current_user.student_role == "admin":
        bucket_all = get_all_size(S3_BUCKET)
    elif current_user.is_authenticated and current_user.student_role == "student":
        bucket_all = dict()
        bucket_all[current_user.student_name] = get_size(S3_BUCKET, current_user.student_name)
    else:
        bucket_all = dict()

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
@app.route(APP_PREFIX + '/web/image/<string:filename>', methods=['GET'])
@login_required
def show_image(filename):
    s3_folder = S3_GLOBAL if current_user.student_role == "admin" else current_user.student_name
    return render_template('image.html', username=s3_folder, filename=secure_filename(filename))


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


# Displays all available students
@app.route(APP_PREFIX + '/web/students', methods=['GET'])
def show_students():
    if current_user.is_authenticated and current_user.student_role == "admin":
        students = Student.query.order_by(Student.student_name.asc())
    else:
        students = Student.query.filter_by(active=1).order_by(Student.student_name.asc())
    return render_template('student.html', students=students)


# Shows information about a specific student
@app.route(APP_PREFIX + '/web/student/<string:student_name>', methods=['GET'])
def show_student(student_name):
    if current_user.is_authenticated and current_user.student_role == "admin":
        student = Student.query.filter_by(student_name=student_name).first()
    else:
        student = Student.query.filter_by(active=1).filter_by(student_name=student_name).first()

    if student:
        if student.student_role == "admin":
            folder_name = S3_GLOBAL
        else:
            folder_name = student.student_name
        return render_template('student_detail.html', folder_name=folder_name, student=student)
    else:
        return render_template('error.html', error_message="That student does not exist.")


# Displays a form to create a new user (aka student)
@app.route(APP_PREFIX + '/web/new_student', methods=['GET', 'POST'])
def show_new_student():
    form = AccountForm()
    if request.method == 'POST' and form.validate_on_submit():
        code = request.form["invitation"]
        invitation = Invitation.query.filter_by(invitation_code=code).first()

        existing_student_1 = Student.query.filter_by(student_mail=escape(request.form["email"])).first()
        existing_student_2 = Student.query.filter_by(student_name=escape(request.form["student"])).first()

        if existing_student_1 is None and existing_student_2 is None:
            if invitation and (invitation.invitation_forever == 1 or invitation.invitation_taken == 0):
                student = Student()
                student.student_name = escape(request.form["student"])
                student.student_mail = escape(request.form["email"])
                student.student_desc = ""
                student.student_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                              salt_length=16)
                student.student_role = invitation.invitation_role
                student.student_img = ""
                student.active = 1
                db.session.add(student)
                db.session.commit()

                invitation.invitation_taken = 1
                db.session.commit()

                send_mail([MAIL_ADMIN], f"{student.student_name} - Registration complete",
                          "A new user has registered using an invitation code. No action necessary.")
            else:
                student = Student()
                student.student_name = escape(request.form["student"])
                student.student_mail = escape(request.form["email"])
                student.student_desc = ""
                student.student_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                              salt_length=16)
                student.student_role = "student"
                student.student_img = ""
                student.active = 0
                db.session.add(student)
                db.session.commit()

                send_mail([MAIL_ADMIN], f"{student.student_name} - Approval required",
                          "A new user has registered, please approve registration.")

                send_mail([student.student_mail], f"{student.student_name} - Registration pending",
                          "Your registration needs to be approved. This should not take too long.")
            return redirect(url_for('show_students'))
        else:
            return render_template('account.html', form=form)
    else:
        return render_template('account.html', form=form)


# Displays various forms to change the currently logged-in user
@app.route(APP_PREFIX + '/web/my_student', methods=['GET'])
@login_required
def show_my_student():
    form1 = MailStudentForm()
    form2 = PassStudentForm()
    form3 = DelStudentForm()
    student = Student.query.filter_by(student_id=current_user.student_id).first()

    form1.email.default = student.student_mail
    form1.description.default = student.student_desc
    if current_user.student_role == "admin":
        form1.image.choices = get_file_choices(S3_GLOBAL)
        form1.image.default = student.student_img
    else:
        form1.image.choices = get_file_choices(student.student_name)
        form1.image.default = student.student_img
    form1.notification.default = student.notification
    form1.process()
    return render_template('account_detail.html', student=student, form1=form1, form2=form2, form3=form3)


# Post a change of user data or display error message if some data was not entered correctly
@app.route(APP_PREFIX + '/web/my_mail_student', methods=['POST'])
@login_required
def show_my_mail_student():
    form1 = MailStudentForm()
    form2 = PassStudentForm()
    form3 = DelStudentForm()
    student = Student.query.filter_by(student_id=current_user.student_id).first()

    if student:
        if form1.validate_on_submit():
            old_mail = student.student_mail
            student.student_mail = escape(request.form["email"])
            student.student_desc = request.form["description"]
            student.student_img = escape(request.form["image"])
            student.notification = 1 if request.form.get('notification') else 0
            db.session.commit()

            send_mail([student.student_mail], "Notification: E-Mail changed",
                      f"You have changed you e-mail address from {old_mail} to {student.student_mail}.")

            return redirect(url_for('show_my_student'))
        else:
            form1.email.default = student.student_mail
            form1.description.default = student.student_desc
            if current_user.student_role == "admin":
                form1.image.choices = get_file_choices(S3_GLOBAL)
                form1.image.default = student.student_img
            else:
                form1.image.choices = get_file_choices(student.student_name)
                form1.image.default = student.student_img
            form1.notification.default = student.notification
            form1.process()
            return render_template('account_detail.html', student=student, form1=form1, form2=form2, form3=form3)
    else:
        return render_template('error.html', error_message="That student does not exist.")


# Post a user's password change or display error message if some data was not entered correctly
@app.route(APP_PREFIX + '/web/my_pass_student', methods=['POST'])
@login_required
def show_my_pass_student():
    form1 = MailStudentForm()
    form2 = PassStudentForm()
    form3 = DelStudentForm()
    student = Student.query.filter_by(student_id=current_user.student_id).first()

    if student:
        if form2.validate_on_submit():
            student.student_pass = generate_password_hash(request.form["password"], method='pbkdf2:sha256',
                                                          salt_length=16)
            db.session.commit()
            return redirect(url_for('show_my_student'))
        else:
            form1.email.default = student.student_mail
            form1.description.default = student.student_desc
            if current_user.student_role == "admin":
                form1.image.choices = get_file_choices(S3_GLOBAL)
                form1.image.default = student.student_img
            else:
                form1.image.choices = get_file_choices(student.student_name)
                form1.image.default = student.student_img
            form1.process()
            return render_template('account_detail.html', student=student, form1=form1, form2=form2, form3=form3)
    else:
        return render_template('error.html', error_message="That student does not exist.")


# Delete a user and return to the site index afterward
@app.route(APP_PREFIX + '/web/my_del_student', methods=['POST'])
@login_required
def show_my_del_student():
    form1 = MailStudentForm()
    form2 = PassStudentForm()
    form3 = DelStudentForm()
    student = Student.query.filter_by(student_id=current_user.student_id).first()

    if student:
        if form3.validate_on_submit():
            Student.query.filter_by(student_id=current_user.student_id).delete()
            db.session.commit()
            logout_user()
            return redirect(url_for('show_index'))
        else:
            form1.email.default = student.student_mail
            form1.description.default = student.student_desc
            if current_user.student_role == "admin":
                form1.image.choices = get_file_choices(S3_GLOBAL)
                form1.image.default = student.student_img
            else:
                form1.image.choices = get_file_choices(student.student_name)
                form1.image.default = student.student_img
            form1.process()
            return render_template('account_detail.html', student=student, form1=form1, form2=form2, form3=form3)
    else:
        return render_template('error.html', error_message="That student does not exist.")


# Approve a user's registration
@app.route(APP_PREFIX + '/web/approve_student/<string:student_name>', methods=['GET'])
@login_required
def show_approve_student(student_name):
    if current_user.student_role == "admin":
        student = Student.query.filter_by(student_name=student_name).first()
        student.active = 1
        db.session.commit()

        send_mail([student.student_mail], f"{student.student_name} - Registration complete",
                  "Your registration has been approved. You can use your login now.")

        return redirect(url_for('show_students'))
    else:
        return render_template('error.html')


# Displays all available organizations
@app.route(APP_PREFIX + '/web/organizations', methods=['GET'])
def show_organizations():
    form = OrganizationForm()

    form.image.choices = get_file_choices(S3_GLOBAL)
    form.image.default = "No Image"
    form.process()

    organizations = Organization.query.order_by(Organization.organization_name.asc())
    return render_template('organization.html', organizations=organizations, form=form)


# Post a new organization - if it doesn't already exist
@app.route(APP_PREFIX + '/web/organizations', methods=['POST'])
@login_required
def show_organizations_p():
    if current_user.student_role == "admin":
        organization_name = escape(request.form["name"])
        organization = Organization.query.filter_by(organization_name=organization_name).first()

        if not organization:
            organization = Organization()
            organization.organization_name = organization_name
            organization.organization_url = clean_url(request.form["url"])
            organization.organization_desc = request.form["description"]
            organization.organization_img = clean_url(request.form["image"])
            organization.student_id = current_user.student_id
            db.session.add(organization)
            db.session.commit()
        return redirect(url_for('show_organizations'))
    else:
        return render_template('error.html', error_message="You are not allowed to perform that operation.")


# Shows information about a specific organization
@app.route(APP_PREFIX + '/web/organization/<string:organization_name>', methods=['GET'])
def show_organization(organization_name):
    form = OrganizationForm()
    organization = Organization.query.filter_by(organization_name=organization_name).first()
    student = Student.query.filter_by(student_id=organization.student_id).first()
    certifications = Certification.query.filter_by(organization_id=organization.organization_id).order_by(Certification.certification_name.asc())

    if organization:
        form.name.default = organization.organization_name
        form.url.default = organization.organization_url
        form.description.default = organization.organization_desc
        form.image.choices = get_file_choices(S3_GLOBAL)
        form.image.default = organization.organization_img
        form.process()
        return render_template('organization_detail.html', organization=organization, certifications=certifications, student=student, folder_name=S3_GLOBAL, form=form)
    else:
        return render_template('error.html', error_message="That organization does not exist.")


# Post a change in a organization's data
@app.route(APP_PREFIX + '/web/organization/<string:organization_name>', methods=['POST'])
@login_required
def show_organization_p(organization_name):
    if current_user.student_role == "admin":
        organization = Organization.query.filter_by(organization_name=organization_name).first()

        if organization:
            organization.organization_name = clean_url(request.form["name"])
            organization.organization_url = clean_url(request.form["url"])
            organization.organization_desc = request.form["description"]
            organization.organization_img = clean_url(request.form["image"])
            db.session.commit()
            return redirect(url_for('show_organization', organization_name=organization.organization_name))
        else:
            return render_template('error.html', error_message="That organization does not exist.")
    else:
        return render_template('error.html', error_message="You are not allowed to perform that operation.")


# Delete a specific organization - and all included elements!!!
@app.route(APP_PREFIX + '/web/deleted_organization/<string:organization_name>', methods=['GET'])
@login_required
def show_deleted_organization(organization_name):
    if current_user.student_role == "admin":
        Organization.query.filter_by(organization_name=organization_name).delete()
        db.session.commit()
        return redirect(url_for('show_organizations'))
    else:
        return render_template('error.html', error_message="You are not allowed to perform that operation.")


# Displays all available certifications
@app.route(APP_PREFIX + '/web/certifications', methods=['GET'])
def show_certifications():
    form = CertificationForm()
    organizations = Organization.query.order_by(Organization.organization_name.asc())

    form.image.choices = get_file_choices(S3_GLOBAL)
    form.image.default = "No Image"
    form.organization.choices = get_organization_choices(organizations)
    form.process()

    certifications = Certification.query.order_by(Certification.certification_name.asc())
    return render_template('certification.html', certifications=certifications, form=form)


# Post a new certification - if it doesn't already exist
@app.route(APP_PREFIX + '/web/certifications', methods=['POST'])
@login_required
def show_certifications_p():
    if current_user.student_role == "admin":
        certification_name = escape(request.form["name"])
        certification = Certification.query.filter_by(certification_name=certification_name).first()

        if not certification:
            certification = Certification()
            certification.certification_name = certification_name
            certification.certification_url = clean_url(request.form["url"])
            certification.certification_desc = request.form["description"]
            certification.certification_img = clean_url(request.form["image"])
            certification.student_id = current_user.student_id
            certification.organization_id = int(escape(request.form["organization"]))
            certification.cycle_length = int(escape(request.form["cycle_length"]))
            certification.requirement_year = int(escape(request.form["requirement_year"]))
            certification.requirement_full = int(escape(request.form["requirement_full"]))

            db.session.add(certification)
            db.session.commit()
        return redirect(url_for('show_certifications'))
    else:
        return render_template('error.html', error_message="You are not allowed to perform that operation.")


# Shows information about a specific certification
@app.route(APP_PREFIX + '/web/certification/<string:certification_name>', methods=['GET'])
def show_certification(certification_name):
    form = CertificationForm()
    certification = Certification.query.filter_by(certification_name=certification_name).first()
    organization = Organization.query.filter_by(organization_id=certification.organization_id).first()
    student = Student.query.filter_by(student_id=organization.student_id).first()
    if certification:
        organizations = Organization.query.order_by(Organization.organization_name.asc())

        form.name.default = certification.certification_name
        form.url.default = certification.certification_url
        form.description.default = certification.certification_desc
        form.image.choices = get_file_choices(S3_GLOBAL)
        form.image.default = certification.certification_img
        form.organization.choices = get_organization_choices(organizations)
        form.organization.default = certification.organization_id
        form.cycle_length.default = int(certification.cycle_length)
        form.requirement_year.default = int(certification.requirement_year)
        form.requirement_full.default = int(certification.requirement_full)

        form.process()
        return render_template('certification_detail.html', certification=certification, student=student, organization=organization, folder_name=S3_GLOBAL, form=form)
    else:
        return render_template('error.html', error_message="That certification does not exist.")


# Post a change in a certification's data
@app.route(APP_PREFIX + '/web/certification/<string:certification_name>', methods=['POST'])
@login_required
def show_certification_p(certification_name):
    if current_user.student_role == "admin":
        certification = Certification.query.filter_by(certification_name=certification_name).first()

        if certification:
            certification.certification_name = clean_url(request.form["name"])
            certification.certification_url = clean_url(request.form["url"])
            certification.certification_desc = request.form["description"]
            certification.certification_img = clean_url(request.form["image"])
            certification.organization_id = int(escape(request.form["organization"]))
            certification.cycle_length = int(escape(request.form["cycle_length"]))
            certification.requirement_year = int(escape(request.form["requirement_year"]))
            certification.requirement_full = int(escape(request.form["requirement_full"]))
            db.session.commit()
            return redirect(url_for('show_certification', certification_name=certification.certification_name))
        else:
            return render_template('error.html', error_message="That certification does not exist.")
    else:
        return render_template('error.html', error_message="You are not allowed to perform that operation.")


# Delete a specific certification - and all included elements!!!
@app.route(APP_PREFIX + '/web/deleted_certification/<string:certification_name>', methods=['GET'])
@login_required
def show_deleted_certification(certification_name):
    if current_user.student_role == "admin":
        Certification.query.filter_by(certification_name=certification_name).delete()
        db.session.commit()
        return redirect(url_for('show_certifications'))
    else:
        return render_template('error.html', error_message="You are not allowed to perform that operation.")

