import re

from flask_wtf import FlaskForm  # integration with WTForms, data validation and CSRF protection
from flask_wtf.file import FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, HiddenField, FileField, TextAreaField, SelectField, \
    IntegerRangeField, DateField, DecimalRangeField, SelectMultipleField
from wtforms.validators import ValidationError, InputRequired, NoneOf, EqualTo, Email, Length, NumberRange, URL


# Custom validator for standard ASCII characters
def ascii_validator(form, field):
    if not re.search(r"^[A-Za-z0-9_.-]+$", field.data):
        raise ValidationError('Please use only letters, numbers or the characters -_.')


def space_ascii_validator(form, field):
    if not re.search(r"^[A-Za-z0-9_. -]*$", field.data):
        raise ValidationError('Please use only letters, numbers or the characters -_.')


def full_ascii_validator(form, field):
    if not re.search(r"^[\S\n\r\t\v ]*$", field.data):
        raise ValidationError('Please use only ASCII letters and numbers.')


# Every form used both in the Flask/Jinja templates as well the main Python app is defined here.
# Not all fields have full validators as they are used in modal windows.

class LoginForm(FlaskForm):
    student = StringField('Name', validators=[InputRequired(), Length(min=5, max=20), ascii_validator])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    remember = BooleanField('Remember me', default='checked')


class PasswordForm(FlaskForm):
    email = StringField('E-Mail', validators=[InputRequired(), Email()])


class PasswordResetForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=8, max=20)])


class AccountForm(FlaskForm):
    student = StringField('Name', validators=[InputRequired(), Length(min=5, max=20),
                                              NoneOf([' '], message='No spaces allowed'), ascii_validator])
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=8, max=20)])
    invitation = StringField('Invitation Code', validators=[InputRequired(), Length(min=5, max=20)], default='guest')


class StudentMailForm(FlaskForm):
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    description = TextAreaField('Description', validators=[Length(max=1024), full_ascii_validator])
    image = SelectField('Image', choices=["none"], validate_choice=False)
    notification = BooleanField('Send notifications', default='checked')
    page_mode = HiddenField(default='init')


class StudentPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=8, max=20)])
    page_mode = HiddenField(default='init')


class StudentDeletionForm(FlaskForm):
    page_mode = HiddenField(default='init')


class FileUploadForm(FlaskForm):
    file = FileField(validators=[FileRequired(), FileAllowed(['png', 'jpg', 'jpeg', 'gif', 'pdf'],
                                                             'Images and Documents only!')])
    page_mode = HiddenField(default='init')


class FileRenameForm(FlaskForm):
    filename_new = StringField('File Name', validators=[InputRequired(), ascii_validator])
    filename_old = HiddenField(default='filename')
    page_mode = HiddenField(default='init')


class ContactForm(FlaskForm):
    contact_name = StringField('Name', validators=[InputRequired(), Length(min=5, max=20), full_ascii_validator])
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    message = TextAreaField('Message', validators=[Length(max=1024), full_ascii_validator])
    check_captcha = HiddenField(default='0')
    captcha = StringField('Captcha', validators=[InputRequired(), EqualTo('check_captcha', message='Captcha does not '
                                                                                                   'match')])


class OrganizationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), ascii_validator])
    url = StringField('URL', validators=[URL()])
    description = TextAreaField('Description', validators=[Length(max=1024), full_ascii_validator])
    image = SelectField('Image', choices=["none"], validate_choice=False)


class CertificationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), ascii_validator])
    url = StringField('URL', validators=[URL()])
    description = TextAreaField('Description', validators=[Length(max=1024), full_ascii_validator])
    image = SelectField('Image', choices=["none"], validate_choice=False)
    organization = SelectField('Select Organization', choices=["none"], validate_choice=False)
    cycle_length = IntegerRangeField('Cycle Length', validators=[NumberRange(min=1, max=3)])
    requirement_year = IntegerRangeField('Required each year', validators=[NumberRange(min=0, max=50)])
    suggested_year = IntegerRangeField('Suggested each year', validators=[NumberRange(min=0, max=50)])
    requirement_full = IntegerRangeField('Required each cycle', validators=[NumberRange(min=10, max=150)])


class CycleForm(FlaskForm):
    certification = SelectField('Select Certification', choices=["none"], validate_choice=False)
    certification_date = DateField('Certification Date', validators=[InputRequired()])
    cycle_start = DateField('Cycle Start', validators=[InputRequired()])


class RecordForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), space_ascii_validator])
    sponsor = StringField('Sponsor', validators=[space_ascii_validator])
    activity_start = DateField('Activity Start', validators=[InputRequired()])
    activity_end = DateField('Activity End', validators=[InputRequired()])
    credits = DecimalRangeField('Credits', validators=[NumberRange(min=0.25, max=20)])
    cycles = SelectMultipleField('Assigned Cycles', choices=["none"], validate_choice=False)
    attachment = SelectField('Image', choices=["none"], validate_choice=False)
    file = FileField(validators=[FileAllowed(['png', 'jpg', 'jpeg', 'gif', 'pdf'], 'Images and Documents only!')])
