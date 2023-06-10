import os  # for direct file system and environment access
import re  # for regular expressions
import random  # for captcha random numbers
import string  # for string operations
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

from forms import LoginForm, AccountForm, StudentMailForm, StudentPasswordForm, StudentDeletionForm, \
    PasswordForm, PasswordResetForm, ContactForm, FileRenameForm, FileUploadForm, \
    OrganizationForm, CertificationForm, CycleForm, RecordForm  # Flask/Jinja template forms


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

# internal error messages
ERR_NOT_EXIST = "That entry does not exist."
ERR_ALREADY_EXIST = "That entry does already exist."
ERR_AUTH = "You are not authorized to perform that action or to view that page."

# internal page modes
PAGE_INIT = "init"
PAGE_MODAL = "modal"
PAGE_MAIL = "mail"
PAGE_PASS = "pass"
PAGE_DELETE = "delete"
PAGE_UPLOAD = "upload"
PAGE_RENAME = "rename"

# internal roles
ROLE_ADMIN = "admin"
ROLE_USER = "student"

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
def json_error_syntax():
    return jsonify({'error': "wrong JSON format"})


def json_error_permissions():
    return jsonify({'error': "wrong credentials or permissions"})



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
        fields = ("organization_id", "student_id", "organization_name", "organization_desc", "organization_url",
                  "organization_img")
        model = Organization


organization_schema = OrganizationSchema()
organizations_schema = OrganizationSchema(many=True)


class OrganizationListResource(Resource):
    @staticmethod
    def get():
        organizations = Organization.query.all()
        return organizations_schema.dump(organizations)

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('organization_name', 'organization_desc', 'organization_url',
                                               'organization_img')):
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
                return json_error_syntax()
        else:
            return json_error_permissions()


class OrganizationResource(Resource):
    @staticmethod
    def get(organization_name):
        organization = Organization.query.filter_by(organization_name=organization_name).first()
        return organization_schema.dump(organization)

    @staticmethod
    def patch(organization_name):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            organization = Organization.query.filter_by(student_id=student.student_id).\
                filter_by(organization_name=organization_name).first()
            if organization and all(s in request.json for s in ('organization_name', 'organization_desc',
                                                                'organization_url', 'organization_img')):
                organization.organization_name = escape(request.json['organization_name'])
                organization.organization_desc = request.json['organization_desc']
                organization.organization_url = clean_url(request.json['organization_url'])
                organization.organization_img = clean_url(request.json['organization_img'])
                db.session.commit()
                return organization_schema.dump(organization)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()

    @staticmethod
    def delete(organization_name):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            organization = Organization.query.filter_by(student_id=student.student_id).\
                filter_by(organization_name=organization_name).first()
            if organization:
                db.session.delete(organization)
                db.session.commit()
                return '', 204
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


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
        fields = ("certification_id", "student_id", "organization_id", "certification_name", "certification_desc",
                  "certification_url", "certification_img", "cycle_length", "requirement_year", "requirement_full")
        model = Certification


certification_schema = CertificationSchema()
certifications_schema = CertificationSchema(many=True)


class CertificationListResource(Resource):
    @staticmethod
    def get():
        certifications = Certification.query.all()
        return certifications_schema.dump(certifications)

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('organization_id', 'certification_name', 'certification_desc',
                                               'certification_url', 'certification_img', 'cycle_length',
                                               'requirement_year', 'requirement_full')):
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
                return json_error_syntax()
        else:
            return json_error_permissions()


class CertificationResource(Resource):
    @staticmethod
    def get(certification_name):
        certification = Certification.query.filter_by(certification_name=certification_name).first()
        return certification_schema.dump(certification)

    @staticmethod
    def patch(certification_name):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            certification = Certification.query.filter_by(student_id=student.student_id).\
                filter_by(certification_name=certification_name).first()
            if certification and all(s in request.json for s in ('organization_id', 'certification_name',
                                                                 'certification_desc', 'certification_url',
                                                                 'certification_img', 'cycle_length',
                                                                 'requirement_year', 'requirement_full')):
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
                return json_error_syntax()
        else:
            return json_error_permissions()

    @staticmethod
    def delete(certification_name):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            certification = Certification.query.filter_by(student_id=student.student_id).\
                filter_by(certification_name=certification_name).first()
            if certification:
                db.session.delete(certification)
                db.session.commit()
                return '', 204
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


api.add_resource(CertificationListResource, APP_PREFIX + '/api/certifications')
api.add_resource(CertificationResource, APP_PREFIX + '/api/certifications/<string:certification_name>')


class Cycle(db.Model):
    __tablename__ = "cycle"
    cycle_id = db.Column(db.INTEGER, primary_key=True)
    student_id = db.Column(db.INTEGER, db.ForeignKey("student.student_id"))
    certification_id = db.Column(db.INTEGER, db.ForeignKey("certification.certification_id"))
    certification_date = db.Column(db.TIMESTAMP)
    cycle_start = db.Column(db.TIMESTAMP)

    def __repr__(self):
        return '<Cycle %s>' % self.cycle_id


class CycleSchema(marsh.Schema):
    class Meta:
        fields = ("cycle_id", "student_id", "certification_id", "certification_date", "cycle_start")
        model = Cycle


cycle_schema = CycleSchema()
cycles_schema = CycleSchema(many=True)


class CycleListResource(Resource):
    @staticmethod
    def get():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            cycles = Cycle.query.filter_by(student_id=student.student_id).all()
            return cycles_schema.dump(cycles)
        else:
            return json_error_permissions()

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('certification_id', 'certification_date', 'cycle_start')):
                new_cycle = Cycle(
                    student_id=student.student_id,
                    certification_id=int(escape(request.json['certification_id'])),
                    certification_date=escape(request.json['certification_date']),
                    cycle_start=escape(request.json['cycle_start'])
                )
                db.session.add(new_cycle)
                db.session.commit()
                return certification_schema.dump(new_cycle)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


class CycleResource(Resource):
    @staticmethod
    def get(cycle_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            cycle = Cycle.query.filter_by(student_id=student.student_id).\
                filter_by(cycle_id=cycle_id).first()
            return cycle_schema.dump(cycle)
        else:
            return json_error_permissions()

    @staticmethod
    def patch(cycle_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            cycle = Cycle.query.filter_by(student_id=student.student_id).\
                filter_by(cycle_id=cycle_id).first()
            if cycle and all(s in request.json for s in ('certification_date', 'cycle_start')):
                cycle.certification_date = escape(request.json['certification_date']),
                cycle.cycle_start = escape(request.json['cycle_start'])
                db.session.commit()
                return cycle_schema.dump(cycle)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()

    @staticmethod
    def delete(cycle_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            cycle = Cycle.query.filter_by(student_id=student.student_id).\
                filter_by(cycle_id=cycle_id).first()
            if cycle:
                db.session.delete(cycle)
                db.session.commit()
                return '', 204
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


api.add_resource(CycleListResource, APP_PREFIX + '/api/cycles')
api.add_resource(CycleResource, APP_PREFIX + '/api/cycles/<int:cycle_id>')


class Record(db.Model):
    __tablename__ = "record"
    record_id = db.Column(db.INTEGER, primary_key=True)
    student_id = db.Column(db.INTEGER, db.ForeignKey("student.student_id"))
    record_name = db.Column(db.VARCHAR(100))
    sponsor = db.Column(db.VARCHAR(100))
    activity_start = db.Column(db.TIMESTAMP)
    activity_end = db.Column(db.TIMESTAMP)
    credits = db.Column(db.DECIMAL(asdecimal=False), default=1.00)
    attachment = db.Column(db.VARCHAR(384))

    def __repr__(self):
        return '<Record %s>' % self.record_name


class RecordSchema(marsh.Schema):
    class Meta:
        fields = ("record_id", "student_id", "record_name", "sponsor", "activity_start", "activity_end",
                  "credits", "attachment")
        model = Record


record_schema = RecordSchema()
records_schema = RecordSchema(many=True)


class RecordListResource(Resource):
    @staticmethod
    def get():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            records = Record.query.filter_by(student_id=student.student_id).all()
            return records_schema.dump(records)
        else:
            return json_error_permissions()

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('record_name', 'sponsor', 'activity_start',
                                               'activity_end', 'credits', 'attachment')):
                new_record = Record(
                    student_id=student.student_id,
                    record_name=escape(request.json['record_name']),
                    sponsor=escape(request.json['sponsor']),
                    activity_start=escape(request.json['activity_start']),
                    activity_end=escape(request.json['activity_end']),
                    credits=float(escape(request.json['credits'])),
                    attachment=escape(request.json['attachment'])
                )
                db.session.add(new_record)
                db.session.commit()
                return record_schema.dump(new_record)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


class RecordResource(Resource):
    @staticmethod
    def get(record_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record = Record.query.filter_by(student_id=student.student_id). \
                filter_by(record_id=record_id).first()
            return record_schema.dump(record)
        else:
            return json_error_permissions()

    @staticmethod
    def patch(record_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record = Record.query.filter_by(student_id=student.student_id). \
                filter_by(record_id=record_id).first()
            if record and all(s in request.json for s in ('record_name', 'sponsor', 'activity_start',
                                                          'activity_end', 'credits', 'attachment')):
                record.record_name = escape(request.json['record_name']),
                record.sponsor = escape(request.json['sponsor']),
                record.activity_start = escape(request.json['activity_start']),
                record.activity_end = escape(request.json['activity_end']),
                record.credits = float(escape(request.json['credits'])),
                record.attachment = escape(request.json['attachment'])
                db.session.commit()
                return record_schema.dump(record)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()

    @staticmethod
    def delete(record_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record = Record.query.filter_by(student_id=student.student_id). \
                filter_by(record_id=record_id).first()
            if record:
                db.session.delete(record)
                db.session.commit()
                return '', 204
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


api.add_resource(RecordListResource, APP_PREFIX + '/api/records')
api.add_resource(RecordResource, APP_PREFIX + '/api/records/<int:record_id>')


class RecordLink(db.Model):
    __tablename__ = "record_link"
    record_link_id = db.Column(db.INTEGER, primary_key=True)
    student_id = db.Column(db.INTEGER, db.ForeignKey("student.student_id"))
    record_id = db.Column(db.INTEGER, db.ForeignKey("record.record_id"))
    cycle_id = db.Column(db.INTEGER, db.ForeignKey("cycle.cycle_id"))

    def __repr__(self):
        return '<Record Link %s>' % self.record_link_id


class RecordLinkSchema(marsh.Schema):
    class Meta:
        fields = ("record_link_id", "student_id", "record_id", "cycle_id")
        model = RecordLink


record_link_schema = RecordLinkSchema()
record_links_schema = RecordLinkSchema(many=True)


class RecordLinkListResource(Resource):
    @staticmethod
    def get():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record_links = RecordLink.query.filter_by(student_id=student.student_id).all()
            return record_links_schema.dump(record_links)
        else:
            return json_error_permissions()

    @staticmethod
    def post():
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            if all(s in request.json for s in ('record_id', 'cycle_id')):
                new_record_link = RecordLink(
                    student_id=student.student_id,
                    record_id=int(escape(request.json['record_id'])),
                    cycle_id=int(escape(request.json['cycle_id']))
                )
                db.session.add(new_record_link)
                db.session.commit()
                return record_schema.dump(new_record_link)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


class RecordLinkResource(Resource):
    @staticmethod
    def get(record_link_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record_link = RecordLink.query.filter_by(student_id=student.student_id). \
                filter_by(record_link_id=record_link_id).first()
            return record_link_schema.dump(record_link)
        else:
            return json_error_permissions()

    @staticmethod
    def patch(record_link_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record_link = RecordLink.query.filter_by(student_id=student.student_id). \
                filter_by(record_link_id=record_link_id).first()
            if record_link and all(s in request.json for s in ('record_id', 'cycle_id')):
                record_link.record_id = int(escape(request.json['record_id'])),
                record_link.cycle_id = int(escape(request.json['cycle_id']))
                db.session.commit()
                return record_link_schema.dump(record_link)
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()

    @staticmethod
    def delete(record_link_id):
        if AuthChecker().check(request.authorization, [ROLE_ADMIN, ROLE_USER]):
            student = Student.query.filter_by(student_name=request.authorization['username']).first()
            record_link = RecordLink.query.filter_by(student_id=student.student_id). \
                filter_by(record_link_id=record_link_id).first()
            if record_link:
                db.session.delete(record_link)
                db.session.commit()
                return '', 204
            else:
                return json_error_syntax()
        else:
            return json_error_permissions()


api.add_resource(RecordLinkListResource, APP_PREFIX + '/api/record_links')
api.add_resource(RecordLinkResource, APP_PREFIX + '/api/record_links/<int:record_link_id>')


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


def get_certification_choices(certifications):
    certifications_choices = list()
    for certification in certifications:
        certifications_choices.append((certification.certification_id, certification.certification_name))
    return certifications_choices


def get_cycle_choices(cycles):
    cycles_choices = list()
    for cycle in cycles:
        certification = Certification.query.filter_by(certification_id=cycle.certification_id).first()
        cycles_choices.append((cycle.cycle_id, certification.certification_name))
    return cycles_choices


def get_certification_dict(certifications):
    certifications_dict = dict()
    for certification in certifications:
        certifications_dict[certification.certification_id] = certification.certification_name
    return certifications_dict


# Internal helpers - style manager
def update_style(style):
    session['style'] = style


# Internal helper - map form data to
def map_form_to_record(record, record_form):
    record.record_name = escape(record_form.name.data)
    record.sponsor = escape(record_form.sponsor.data)
    record.activity_start = escape(record_form.activity_start.data)
    record.activity_end = escape(record_form.activity_end.data)
    record.credits = float(escape(record_form.credits.data))


def map_record_to_form(record, record_form):
    record_form.name.default = record.record_name
    record_form.sponsor.default = record.sponsor
    record_form.activity_start.default = record.activity_start
    record_form.activity_end.default = record.activity_end
    record_form.credits.default = record.credits


def map_record_defaults(record_form):
    record_form.name.default = record_form.name.data
    record_form.sponsor.default = record_form.sponsor.data
    record_form.activity_start.default = record_form.activity_start.data
    record_form.activity_end.default = record_form.activity_end.data
    record_form.credits.default = record_form.credits.data


def map_form_to_cycle(cycle, cycle_form):
    cycle.certification_id = int(cycle_form.certification.data)
    cycle.certification_date = escape(cycle_form.certification_date.data)
    cycle.cycle_start = escape(cycle_form.cycle_start.data)


def map_cycle_to_form(cycle, cycle_form):
    cycle_form.certification.default = cycle.certification_id
    cycle_form.certification_date.default = cycle.certification_date
    cycle_form.cycle_start.default = cycle.cycle_start


def map_cycle_defaults(cycle_form):
    cycle_form.certification.default = cycle_form.certification.data
    cycle_form.certification_date.default = cycle_form.certification_date.data
    cycle_form.cycle_start.default = cycle_form.cycle_start.data


def map_form_to_certification(certification, certification_form):
    certification.certification_name = escape(certification_form.name.data)
    certification.certification_url = clean_url(certification_form.url.data)
    certification.certification_desc = certification_form.description.data
    certification.certification_img = clean_url(certification_form.image.data)
    certification.student_id = current_user.student_id
    certification.organization_id = int(escape(certification_form.organization.data))
    certification.cycle_length = int(escape(certification_form.cycle_length.data))
    certification.requirement_year = int(escape(certification_form.requirement_year.data))
    certification.requirement_full = int(escape(certification_form.requirement_full.data))


def map_certification_to_form(certification, certification_form):
    certification_form.name.default = certification.certification_name
    certification_form.url.default = certification.certification_url
    certification_form.description.default = certification.certification_desc
    certification_form.image.default = certification.certification_img
    certification_form.organization.default = certification.organization_id
    certification_form.cycle_length.default = int(certification.cycle_length)
    certification_form.requirement_year.default = int(certification.requirement_year)
    certification_form.requirement_full.default = int(certification.requirement_full)


def map_certification_defaults(certification_form):
    certification_form.name.default = certification_form.name.data
    certification_form.url.default = certification_form.url.data
    certification_form.description.default = certification_form.description.data
    certification_form.image.default = certification_form.image.data
    certification_form.organization.default = certification_form.organization.data
    certification_form.cycle_length.default = certification_form.cycle_length.data
    certification_form.requirement_year.default = certification_form.requirement_year.data
    certification_form.requirement_full.default = certification_form.requirement_full.data


def map_form_to_organization(organization, organization_form):
    organization.organization_name = escape(organization_form.name.data)
    organization.organization_url = clean_url(organization_form.url.data)
    organization.organization_desc = organization_form.description.data
    organization.organization_img = clean_url(organization_form.image.data)


def map_organization_to_form(organization, organization_form):
    organization_form.name.default = organization.organization_name
    organization_form.url.default = organization.organization_url
    organization_form.description.default = organization.organization_desc
    organization_form.image.default = organization.organization_img


def map_organization_defaults(organization_form):
    organization_form.name.default = organization_form.name.data
    organization_form.url.default = organization_form.url.data
    organization_form.description.default = organization_form.description.data
    organization_form.image.default = organization_form.image.data


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
    login_form = LoginForm()
    if request.method == 'POST' and login_form.validate_on_submit():
        student_name = login_form.student.data
        student_pass = login_form.password.data
        remember = login_form.remember.data
        student = Student.query.filter_by(active=1).filter_by(student_name=student_name).first()

        if not student or not check_password_hash(student.student_pass, student_pass):
            return redirect(url_for('show_login'))
        else:
            if student.student_role == ROLE_ADMIN:
                update_style("main_admin.css")
            else:
                update_style("main.css")

            login_user(student, remember=remember)
            return redirect(url_for('show_index'))
    else:
        login_form.student.default = login_form.student.data
        login_form.remember.default = login_form.remember.data
        login_form.process()
        return render_template('login.html', login_form=login_form)


# Log out user and return to the site index afterward
@app.route(APP_PREFIX + '/web/logout', methods=['GET'])
def show_logout():
    update_style("main.css")
    logout_user()
    return redirect(url_for('show_index'))


# Show user password reset page
@app.route(APP_PREFIX + '/web/password', methods=['GET', 'POST'])
def show_password():
    password_form = PasswordForm()
    if request.method == 'POST' and password_form.validate_on_submit():
        if MAIL_ENABLE == 1:
            student_email = password_form.email.data

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
        return render_template('password.html', password_form=password_form)


# Show user password reset page
@app.route(APP_PREFIX + '/web/reset_password/<string:random_hash>', methods=['GET', 'POST'])
def show_password_reset(random_hash):
    password_reset_form = PasswordResetForm()
    if request.method == 'POST' and password_reset_form.validate_on_submit():
        students = Student.query.filter_by(active=1).order_by(Student.student_name.asc())
        for student in students:
            if student.password_reset == random_hash and len(random_hash) > 30:
                student.student_pass = generate_password_hash(password_reset_form.password.data, method='pbkdf2:sha256',
                                                              salt_length=16)
                student.password_reset = ""
                db.session.commit()
        return redirect(url_for('show_index'))
    else:
        return render_template('password_reset.html', password_reset_form=password_reset_form, random_hash=random_hash)


# --------------------------------------------------------------
# S3 storage pages
# --------------------------------------------------------------

# Show list of all uploaded filed and upload form
@app.route(APP_PREFIX + "/web/storage", methods=['GET', 'POST'])
@login_required
def show_storage():
    file_upload_form = FileUploadForm()
    file_rename_form = FileRenameForm()
    s3_folder = S3_GLOBAL if current_user.student_role == ROLE_ADMIN else current_user.student_name
    space_used_in_mb = round((get_size(S3_BUCKET, f"{s3_folder}/") / 1024 / 1024), 2)
    space_used = int(space_used_in_mb / int(S3_QUOTA) * 100)

    if request.method == 'POST' and file_upload_form.page_mode.data == PAGE_UPLOAD and \
            file_upload_form.validate_on_submit():
        filename = secure_filename(file_upload_form.file.data.filename)

        if allowed_file(filename) and space_used < 100:
            local_folder_name = f"{UPLOAD_FOLDER}/{s3_folder}"
            local_file = os.path.join(local_folder_name, filename)
            remote_file = f"{s3_folder}/{filename}"
            if not os.path.exists(local_folder_name):
                os.makedirs(local_folder_name)
            file_upload_form.file.data.save(local_file)
            upload_file(S3_BUCKET, remote_file, local_file)

        return redirect(url_for('show_storage'))
    elif request.method == 'POST' and file_rename_form.page_mode.data == PAGE_RENAME and \
            file_rename_form.validate_on_submit():
        remote_file_new = f"{secure_filename(s3_folder)}/{secure_filename(file_rename_form.filename_new.data)}"
        remote_file_old = f"{secure_filename(s3_folder)}/{secure_filename(file_rename_form.filename_old.data)}"
        if remote_file_new != remote_file_old and allowed_file(remote_file_new):
            log_entry(__name__, [S3_BUCKET, remote_file_new, remote_file_old])
            rename_file(S3_BUCKET, remote_file_new, remote_file_old)

        return redirect(url_for('show_storage'))
    else:
        if file_upload_form.page_mode.data == PAGE_UPLOAD:
            page_mode = PAGE_UPLOAD
        elif file_rename_form.page_mode.data == PAGE_RENAME:
            page_mode = PAGE_RENAME
            file_rename_form.filename_new.default = file_rename_form.filename_new.data
            file_rename_form.filename_old.default = file_rename_form.filename_old.data
            file_rename_form.process()
        else:
            page_mode = PAGE_INIT
        contents = list_files(S3_BUCKET, s3_folder)
        return render_template('storage.html',
                               contents=contents, space_used_in_mb=space_used_in_mb, space_used=space_used,
                               page_mode=page_mode, file_upload_form=file_upload_form,
                               file_rename_form=file_rename_form)


# Download a specific file from S3 storage
@app.route(APP_PREFIX + "/web/download/<string:filename>", methods=['GET'])
@login_required
def do_download(filename):
    s3_folder = S3_GLOBAL if current_user.student_role == ROLE_ADMIN else current_user.student_name
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
            return render_template('error.html', error_message=ERR_AUTH)

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
    s3_folder = S3_GLOBAL if current_user.student_role == ROLE_ADMIN else current_user.student_name
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

    if current_user.is_authenticated and current_user.student_role == ROLE_ADMIN:
        bucket_all = get_all_size(S3_BUCKET)
    elif current_user.is_authenticated and current_user.student_role == ROLE_USER:
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
    s3_folder = S3_GLOBAL if current_user.student_role == ROLE_ADMIN else current_user.student_name
    return render_template('image.html', username=s3_folder, filename=secure_filename(filename))


# Displays a form to send a message to the site admin - implements a simple captcha as well
@app.route(APP_PREFIX + '/web/contact', methods=['GET', 'POST'])
def show_contact():
    contact_form = ContactForm()
    if request.method == 'POST':
        if contact_form.validate_on_submit():
            contact_name = escape(contact_form.contact_name.data)
            email = escape(contact_form.email.data)
            message = escape(contact_form.message.data)

            send_mail([MAIL_ADMIN], f"{contact_name} - {email}",
                      f"{message}")

            return redirect(url_for('show_index'))
        else:
            contact_form.contact_name.default = escape(contact_form.contact_name.data)
            contact_form.email.default = escape(contact_form.email.data)
            contact_form.message.default = escape(contact_form.message.data)

            random1 = random.randint(1, 10)
            random2 = random.randint(1, 10)
            check_captcha = random1 + random2

            contact_form.check_captcha.default = check_captcha
            contact_form.process()

            return render_template('contact.html', contact_form=contact_form, random1=random1, random2=random2,
                                   check_captcha=check_captcha)
    else:
        random1 = random.randint(1, 10)
        random2 = random.randint(1, 10)
        check_captcha = random1 + random2

        contact_form.check_captcha.default = check_captcha
        contact_form.process()

        return render_template('contact.html', contact_form=contact_form, random1=random1, random2=random2,
                               check_captcha=check_captcha)


# Displays all available students
@app.route(APP_PREFIX + '/web/students', methods=['GET'])
def show_students():
    if current_user.is_authenticated and current_user.student_role == ROLE_ADMIN:
        students = Student.query.order_by(Student.student_name.asc())
    else:
        students = Student.query.filter_by(active=1).order_by(Student.student_name.asc())
    return render_template('student.html', students=students)


# Shows information about a specific student
@app.route(APP_PREFIX + '/web/student/<string:student_name>', methods=['GET'])
def show_student(student_name):
    if current_user.is_authenticated and current_user.student_role == ROLE_ADMIN:
        student = Student.query.filter_by(student_name=student_name).first()
    else:
        student = Student.query.filter_by(active=1).filter_by(student_name=student_name).first()

    if student:
        if student.student_role == ROLE_ADMIN:
            folder_name = S3_GLOBAL
        else:
            folder_name = student.student_name
        return render_template('student_detail.html', folder_name=folder_name, student=student)
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Displays a form to create a new user (aka student)
@app.route(APP_PREFIX + '/web/new_student', methods=['GET', 'POST'])
def show_new_student():
    account_form = AccountForm()
    if request.method == 'POST' and account_form.validate_on_submit():
        code = account_form.invitation.data
        invitation = Invitation.query.filter_by(invitation_code=code).first()

        existing_student_1 = Student.query.filter_by(student_mail=escape(account_form.email.data)).first()
        existing_student_2 = Student.query.filter_by(student_name=escape(account_form.student.data)).first()

        if existing_student_1 is None and existing_student_2 is None:
            if invitation and (invitation.invitation_forever == 1 or invitation.invitation_taken == 0):
                student = Student()
                student.student_name = escape(account_form.student.data)
                student.student_mail = escape(account_form.email.data)
                student.student_desc = ""
                student.student_pass = generate_password_hash(account_form.password.data, method='pbkdf2:sha256',
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
                student.student_name = escape(account_form.student.data)
                student.student_mail = escape(account_form.email.data)
                student.student_desc = ""
                student.student_pass = generate_password_hash(account_form.password.data, method='pbkdf2:sha256',
                                                              salt_length=16)
                student.student_role = ROLE_USER
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
            return render_template('account.html', account_form=account_form)
    else:
        return render_template('account.html', account_form=account_form)


# Displays various forms to change the currently logged-in user
@app.route(APP_PREFIX + '/web/my_student', methods=['GET', 'POST'])
@login_required
def show_my_student():
    student_mail_form = StudentMailForm()
    student_password_form = StudentPasswordForm()
    student_deletion_form = StudentDeletionForm()
    student = Student.query.filter_by(student_id=current_user.student_id).first()

    if request.method == 'POST' and student_mail_form.page_mode.data == PAGE_MAIL and \
            student_mail_form.validate_on_submit():
        old_mail = student.student_mail
        student.student_mail = escape(student_mail_form.email.data)
        student.student_desc = student_mail_form.description.data
        student.student_img = escape(student_mail_form.image.data)
        student.notification = int(student_mail_form.notification.data)
        db.session.commit()

        send_mail([student.student_mail], "Notification: E-Mail changed",
                  f"You have changed you e-mail address from {old_mail} to {student.student_mail}.")

        return redirect(url_for('show_my_student'))
    elif request.method == 'POST' and student_password_form.page_mode.data == PAGE_PASS and \
            student_password_form.validate_on_submit():
        student.student_pass = generate_password_hash(student_password_form.password.data, method='pbkdf2:sha256',
                                                      salt_length=16)
        db.session.commit()
        return redirect(url_for('show_my_student'))
    elif request.method == 'POST' and student_deletion_form.page_mode.data == PAGE_DELETE and \
            student_deletion_form.validate_on_submit():
        Student.query.filter_by(student_id=current_user.student_id).delete()
        db.session.commit()
        logout_user()
        return redirect(url_for('show_index'))
    else:
        if student_mail_form.page_mode.data == PAGE_MAIL:
            page_mode = PAGE_MAIL
        elif student_password_form.page_mode.data == PAGE_PASS:
            page_mode = PAGE_PASS
        elif student_deletion_form.page_mode.data == PAGE_DELETE:
            page_mode = PAGE_DELETE
        else:
            page_mode = PAGE_INIT

        student_mail_form.email.default = student.student_mail
        student_mail_form.description.default = student.student_desc
        if current_user.student_role == ROLE_ADMIN:
            student_mail_form.image.choices = get_file_choices(S3_GLOBAL)
            student_mail_form.image.default = student.student_img
        else:
            student_mail_form.image.choices = get_file_choices(student.student_name)
            student_mail_form.image.default = student.student_img
        student_mail_form.notification.default = student.notification
        student_mail_form.process()
        return render_template('account_detail.html', student=student, page_mode=page_mode,
                               student_mail_form=student_mail_form, student_password_form=student_password_form,
                               student_deletion_form=student_deletion_form)


# Approve a user's registration
@app.route(APP_PREFIX + '/web/approve_student/<string:student_name>', methods=['GET'])
@login_required
def show_approve_student(student_name):
    if current_user.student_role == ROLE_ADMIN:
        student = Student.query.filter_by(student_name=student_name).first()
        student.active = 1
        db.session.commit()

        send_mail([student.student_mail], f"{student.student_name} - Registration complete",
                  "Your registration has been approved. You can use your login now.")

        return redirect(url_for('show_students'))
    else:
        return render_template('error.html', error_message=ERR_AUTH)


# Displays all available organizations
@app.route(APP_PREFIX + '/web/organizations', methods=['GET'])
def show_organizations():
    organization_form = OrganizationForm()
    organization_form.image.choices = get_file_choices(S3_GLOBAL)
    organization_form.image.default = "No Image"
    organization_form.process()
    organizations = Organization.query.order_by(Organization.organization_name.asc())

    return render_template('organization.html', organizations=organizations, page_mode=PAGE_INIT,
                           organization_form=organization_form)


# Post a new organization - if it doesn't already exist
@app.route(APP_PREFIX + '/web/organizations', methods=['POST'])
@login_required
def show_organizations_p():
    organization_form = OrganizationForm()
    organizations = Organization.query.order_by(Organization.organization_name.asc())

    if current_user.student_role == ROLE_ADMIN and organization_form.validate_on_submit():
        organization_name = escape(organization_form.name.data)
        organization = Organization.query.filter_by(organization_name=organization_name).first()

        if not organization:
            organization = Organization()
            organization.student_id = current_user.student_id
            map_form_to_organization(organization, organization_form)
            db.session.add(organization)
            db.session.commit()
        return redirect(url_for('show_organizations'))
    else:
        organization_form.image.choices = get_file_choices(S3_GLOBAL)
        map_organization_defaults(organization_form)
        organization_form.process()
        return render_template('organization.html', organizations=organizations, page_mode=PAGE_MODAL,
                               organization_form=organization_form)


# Shows information about a specific organization
@app.route(APP_PREFIX + '/web/organization/<string:organization_name>', methods=['GET'])
def show_organization(organization_name):
    organization_form = OrganizationForm()
    organization = Organization.query.filter_by(organization_name=organization_name).first()
    student = Student.query.filter_by(student_id=organization.student_id).first()
    certifications = Certification.query.filter_by(organization_id=organization.organization_id)\
        .order_by(Certification.certification_name.asc())

    if organization:
        organization_form.image.choices = get_file_choices(S3_GLOBAL)
        map_organization_to_form(organization, organization_form)
        organization_form.process()
        return render_template('organization_detail.html', organization=organization, certifications=certifications,
                               student=student, folder_name=S3_GLOBAL, page_mode=PAGE_INIT,
                               organization_form=organization_form)
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Post a change in an organization's data
@app.route(APP_PREFIX + '/web/organization/<string:organization_name>', methods=['POST'])
@login_required
def show_organization_p(organization_name):
    organization_form = OrganizationForm()
    organization = Organization.query.filter_by(organization_name=organization_name).first()
    student = Student.query.filter_by(student_id=organization.student_id).first()
    certifications = Certification.query.filter_by(organization_id=organization.organization_id) \
        .order_by(Certification.certification_name.asc())

    if current_user.student_role == ROLE_ADMIN and organization_form.validate_on_submit():
        if organization:
            map_form_to_organization(organization, organization_form)
            db.session.commit()
            return redirect(url_for('show_organization', organization_name=organization.organization_name))
        else:
            return render_template('error.html', error_message=ERR_NOT_EXIST)
    else:
        organization_form.image.choices = get_file_choices(S3_GLOBAL)
        map_organization_defaults(organization_form)
        organization_form.process()
        return render_template('organization_detail.html', organization=organization, certifications=certifications,
                               student=student, folder_name=S3_GLOBAL, page_mode=PAGE_MODAL,
                               organization_form=organization_form)


# Delete a specific organization - and all included elements!!!
@app.route(APP_PREFIX + '/web/delete_organization/<string:organization_name>', methods=['GET'])
@login_required
def delete_organization(organization_name):
    organization = Organization.query.filter_by(organization_name=organization_name).first()

    if organization:
        Organization.query.filter_by(organization_name=organization_name).delete()
        db.session.commit()
        return redirect(url_for('show_organizations'))
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Displays all available certifications
@app.route(APP_PREFIX + '/web/certifications', methods=['GET'])
def show_certifications():
    certification_form = CertificationForm()
    organizations = Organization.query.order_by(Organization.organization_name.asc())
    certification_form.image.choices = get_file_choices(S3_GLOBAL)
    certification_form.image.default = "No Image"
    certification_form.organization.choices = get_organization_choices(organizations)
    certification_form.process()
    certifications = Certification.query.order_by(Certification.certification_name.asc())

    return render_template('certification.html', certifications=certifications, page_mode=PAGE_INIT,
                           certification_form=certification_form)


# Post a new certification - if it doesn't already exist
@app.route(APP_PREFIX + '/web/certifications', methods=['POST'])
@login_required
def show_certifications_p():
    certification_form = CertificationForm()
    organizations = Organization.query.order_by(Organization.organization_name.asc())
    certifications = Certification.query.order_by(Certification.certification_name.asc())

    if current_user.student_role == ROLE_ADMIN and certification_form.validate_on_submit():
        certification_name = escape(certification_form.name.data)
        certification = Certification.query.filter_by(certification_name=certification_name).first()

        if not certification:
            certification = Certification()
            certification.student_id = current_user.student_id
            map_form_to_certification(certification, certification_form)
            db.session.add(certification)
            db.session.commit()
        return redirect(url_for('show_certifications'))
    else:
        certification_form.image.choices = get_file_choices(S3_GLOBAL)
        certification_form.organization.choices = get_organization_choices(organizations)
        map_certification_defaults(certification_form)
        certification_form.process()
        return render_template('certification.html', certifications=certifications, page_mode=PAGE_MODAL,
                               certification_form=certification_form)


# Shows information about a specific certification
@app.route(APP_PREFIX + '/web/certification/<string:certification_name>', methods=['GET'])
def show_certification(certification_name):
    certification_form = CertificationForm()
    certification = Certification.query.filter_by(certification_name=certification_name).first()
    organization = Organization.query.filter_by(organization_id=certification.organization_id).first()
    student = Student.query.filter_by(student_id=organization.student_id).first()

    if certification:
        organizations = Organization.query.order_by(Organization.organization_name.asc())
        certification_form.image.choices = get_file_choices(S3_GLOBAL)
        certification_form.organization.choices = get_organization_choices(organizations)
        map_certification_to_form(certification, certification_form)
        certification_form.process()
        return render_template('certification_detail.html', certification=certification, student=student,
                               organization=organization, folder_name=S3_GLOBAL, page_mode=PAGE_INIT,
                               certification_form=certification_form)
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Post a change in a certification's data
@app.route(APP_PREFIX + '/web/certification/<string:certification_name>', methods=['POST'])
@login_required
def show_certification_p(certification_name):
    certification_form = CertificationForm()
    certification = Certification.query.filter_by(certification_name=certification_name).first()
    organization = Organization.query.filter_by(organization_id=certification.organization_id).first()
    student = Student.query.filter_by(student_id=organization.student_id).first()
    organizations = Organization.query.order_by(Organization.organization_name.asc())

    if current_user.student_role == ROLE_ADMIN and certification_form.validate_on_submit():
        certification = Certification.query.filter_by(certification_name=certification_name).first()

        if certification:
            map_form_to_certification(certification, certification_form)
            db.session.commit()
            return redirect(url_for('show_certification', certification_name=certification.certification_name))
        else:
            return render_template('error.html', error_message=ERR_NOT_EXIST)
    else:
        certification_form.image.choices = get_file_choices(S3_GLOBAL)
        certification_form.organization.choices = get_organization_choices(organizations)
        map_certification_defaults(certification_form)
        certification_form.process()
        return render_template('certification_detail.html', certification=certification, student=student,
                               organization=organization, folder_name=S3_GLOBAL, page_mode=PAGE_MODAL,
                               certification_form=certification_form)


# Delete a specific certification - and all included elements!!!
@app.route(APP_PREFIX + '/web/delete_certification/<string:certification_name>', methods=['GET'])
@login_required
def delete_certification(certification_name):
    certification = Certification.query.filter_by(certification_name=certification_name).first()

    if certification:
        Certification.query.filter_by(certification_name=certification_name).delete()
        db.session.commit()
        return redirect(url_for('show_certifications'))
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Displays all my cycles
@app.route(APP_PREFIX + '/web/cycles', methods=['GET'])
@login_required
def show_cycles():
    cycle_form = CycleForm()
    certifications = Certification.query.order_by(Certification.certification_name.asc())
    cert_dict = get_certification_dict(certifications)
    cycle_form.certification.choices = get_certification_choices(certifications)
    cycle_form.process()
    cycles = Cycle.query.filter_by(student_id=current_user.student_id).order_by(Cycle.cycle_id.asc())

    return render_template('cycle.html', cycles=cycles, cert_dict=cert_dict, page_mode=PAGE_INIT, cycle_form=cycle_form)


# Post a new cycle - if it doesn't already exist
@app.route(APP_PREFIX + '/web/cycles', methods=['POST'])
@login_required
def show_cycles_p():
    cycle_form = CycleForm()
    certifications = Certification.query.order_by(Certification.certification_name.asc())
    cert_dict = get_certification_dict(certifications)
    cycles = Cycle.query.filter_by(student_id=current_user.student_id).order_by(Cycle.cycle_id.asc())

    if current_user.student_role in [ROLE_ADMIN, ROLE_USER] and cycle_form.validate_on_submit():
        certification_id = int(escape(cycle_form.certification.data))
        cycle = Cycle.query.filter_by(student_id=current_user.student_id).filter_by(certification_id=certification_id).\
            first()

        if not cycle:
            cycle = Cycle()
            cycle.student_id = current_user.student_id
            map_form_to_cycle(cycle, cycle_form)
            db.session.add(cycle)
            db.session.commit()
        return redirect(url_for('show_cycles'))
    else:
        cycle_form.certification.choices = get_certification_choices(certifications)
        map_cycle_defaults(cycle_form)
        cycle_form.process()
        return render_template('cycle.html', cycles=cycles, cert_dict=cert_dict, page_mode=PAGE_MODAL,
                               cycle_form=cycle_form)


# Shows information about a specific cycle
@app.route(APP_PREFIX + '/web/cycle/<int:cycle_id>', methods=['GET'])
@login_required
def show_cycle(cycle_id):
    cycle_form = CycleForm()
    cycle = Cycle.query.filter_by(student_id=current_user.student_id).filter_by(cycle_id=cycle_id).first()
    certifications = Certification.query.order_by(Certification.certification_name.asc())
    cert_dict = get_certification_dict(certifications)

    if cycle:
        student = Student.query.filter_by(student_id=cycle.student_id).first()

        cycle_form.certification.choices = get_certification_choices(certifications)
        map_cycle_to_form(cycle, cycle_form)
        cycle_form.process()
        return render_template('cycle_detail.html', cycle=cycle, cert_dict=cert_dict, student=student,
                               page_mode=PAGE_INIT, cycle_form=cycle_form)
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Post a change in a cycle's data
@app.route(APP_PREFIX + '/web/cycle/<int:cycle_id>', methods=['POST'])
@login_required
def show_cycle_p(cycle_id):
    cycle_form = CycleForm()
    cycle = Cycle.query.filter_by(student_id=current_user.student_id).filter_by(cycle_id=cycle_id).first()
    student = Student.query.filter_by(student_id=cycle.student_id).first() if cycle else None
    certifications = Certification.query.order_by(Certification.certification_name.asc())
    cert_dict = get_certification_dict(certifications)

    if current_user.student_role in [ROLE_ADMIN, ROLE_USER] and cycle_form.validate_on_submit():
        if cycle:
            map_form_to_cycle(cycle, cycle_form)
            db.session.commit()
            return redirect(url_for('show_cycle', cycle_id=cycle.cycle_id))
        else:
            return render_template('error.html', error_message=ERR_NOT_EXIST)
    else:
        cycle_form.certification.choices = get_certification_choices(certifications)
        map_cycle_defaults(cycle_form)
        cycle_form.process()
        return render_template('cycle_detail.html', cycle=cycle, cert_dict=cert_dict, student=student,
                               page_mode=PAGE_MODAL, cycle_form=cycle_form)


# Delete a specific cycle
@app.route(APP_PREFIX + '/web/delete_cycle/<int:cycle_id>', methods=['GET'])
@login_required
def delete_cycle(cycle_id):
    cycle = Cycle.query.filter_by(student_id=current_user.student_id).filter_by(cycle_id=cycle_id).first()

    if cycle:
        Cycle.query.filter_by(student_id=current_user.student_id).filter_by(cycle_id=cycle_id).delete()
        db.session.commit()
        return redirect(url_for('show_cycles'))
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Displays all my records
@app.route(APP_PREFIX + '/web/records', methods=['GET'])
@login_required
def show_records():
    records = Record.query.filter_by(student_id=current_user.student_id).order_by(Record.record_id.asc())

    return render_template('record.html', records=records)


# Shows information about a specific record
@app.route(APP_PREFIX + '/web/record/<int:record_id>', methods=['GET'])
@login_required
def show_record(record_id):
    record = Record.query.filter_by(student_id=current_user.student_id).filter_by(record_id=record_id).first()

    if record:
        student = Student.query.filter_by(student_id=record.student_id).first()
        return render_template('record_detail.html', record=record, student=student)
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)


# Post a change in a record's data
@app.route(APP_PREFIX + '/web/edit_record/<int:record_id>', methods=['GET', 'POST'])
@login_required
def edit_record(record_id):
    record_form = RecordForm()
    cycles = Cycle.query.filter_by(student_id=current_user.student_id).order_by(Cycle.cycle_id.asc())

    if request.method == 'GET' and record_id == 0:
        record_form.cycles.choices = get_cycle_choices(cycles)
        record_form.process()

        return render_template('record_edit.html', record_id=record_id, record_form=record_form)
    elif request.method == 'GET' and record_id > 0:
        record = Record.query.filter_by(student_id=current_user.student_id).filter_by(record_id=record_id).first()

        if record:
            record_form.cycles.choices = get_cycle_choices(cycles)
            record_links = RecordLink.query.filter_by(student_id=current_user.student_id).filter_by(
                record_id=record_id).order_by(RecordLink.record_id.asc())
            record_links_list = list()
            for record_link in record_links:
                record_links_list.append(record_link.cycle_id)
            record_form.cycles.default = record_links_list

            map_record_to_form(record, record_form)
            record_form.process()

            return render_template('record_edit.html', record_id=record_id, record_form=record_form)
        else:
            return render_template('error.html', error_message=ERR_NOT_EXIST)
    elif request.method == 'POST':
        if record_form.validate_on_submit() and current_user.student_role in [ROLE_ADMIN, ROLE_USER] and record_id == 0:
            record_name = escape(record_form.name.data)
            activity_end = escape(record_form.activity_end.data)
            record = Record.query.filter_by(student_id=current_user.student_id).filter_by(record_name=record_name). \
                filter_by(activity_end=activity_end).first()

            if not record:
                record = Record()
                record.student_id = current_user.student_id
                map_form_to_record(record, record_form)
                db.session.add(record)
                db.session.commit()

                for cycle in record_form.cycles.data:
                    record_link = RecordLink()
                    record_link.student_id = current_user.student_id
                    record_link.record_id = record.record_id
                    record_link.cycle_id = cycle

                    db.session.add(record_link)
                    db.session.commit()

                return redirect(url_for('show_records'))
            else:
                return render_template('error.html', error_message=ERR_ALREADY_EXIST)
        elif record_form.validate_on_submit() and current_user.student_role in [ROLE_ADMIN, ROLE_USER] and record_id > 0:
            record = Record.query.filter_by(student_id=current_user.student_id).filter_by(record_id=record_id).first()

            if record:
                map_form_to_record(record, record_form)
                db.session.commit()

                RecordLink.query.filter_by(student_id=current_user.student_id).filter_by(record_id=record_id).delete()
                db.session.commit()

                for cycle in record_form.cycles.data:
                    record_link = RecordLink()
                    record_link.student_id = current_user.student_id
                    record_link.record_id = record.record_id
                    record_link.cycle_id = cycle

                    db.session.add(record_link)
                    db.session.commit()

                return redirect(url_for('show_record', record_id=record.record_id))
            else:
                return render_template('error.html', error_message=ERR_NOT_EXIST)
        else:
            map_record_defaults(record_form)
            record_form.process()

            return render_template('record_edit.html', record_id=record_id, record_form=record_form)
    else:
        return render_template('error.html')


# Delete a specific record
@app.route(APP_PREFIX + '/web/delete_record/<int:record_id>', methods=['GET'])
@login_required
def delete_record(record_id):
    record = Record.query.filter_by(student_id=current_user.student_id).filter_by(record_id=record_id).first()

    if record:
        Record.query.filter_by(student_id=current_user.student_id).filter_by(record_id=record_id).delete()
        db.session.commit()
        return redirect(url_for('show_records'))
    else:
        return render_template('error.html', error_message=ERR_NOT_EXIST)
