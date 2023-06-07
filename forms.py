import re

from flask_wtf import FlaskForm  # integration with WTForms, data validation and CSRF protection
from flask_wtf.file import FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, HiddenField, FileField, TextAreaField, SelectField, \
    IntegerRangeField, DateField
from wtforms.validators import ValidationError, InputRequired, NoneOf, EqualTo, Email, Length, NumberRange, DataRequired


# Custom validator for standard ASCII characters
def ascii_validator(form, field):
    if not re.search(r"^[A-Za-z0-9_.-]+$", field.data):
        raise ValidationError('Please use only letters, numbers or the characters -_.')


def full_ascii_validator(form, field):
    if not re.search(r"^[ -~]*$", field.data):
        raise ValidationError('Please use only ASCII letters and numbers.')


def url_ascii_validator(form, field):
    if not re.search(r"^[0-9A-Za-z-\\\/.@:%_\+~#=]*$", field.data):
        raise ValidationError('Please use only valid URLs.')


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


class MailStudentForm(FlaskForm):
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    description = TextAreaField('Description', validators=[Length(max=1024), full_ascii_validator])
    image = SelectField('Image', choices=["none"], validate_choice=False)
    notification = BooleanField('Send notifications', default='checked')


class PassStudentForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=8, max=20)])
    operation = HiddenField(default='pass')


class DelStudentForm(FlaskForm):
    operation = HiddenField(default='delete')


class UploadForm(FlaskForm):
    file = FileField(validators=[FileRequired(), FileAllowed(['jpg', 'png', 'gif'], 'Images only!')])


class ContactForm(FlaskForm):
    contact_name = StringField('Name', validators=[InputRequired(), Length(min=5, max=20), full_ascii_validator])
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    message = TextAreaField('Message', validators=[Length(max=1024), full_ascii_validator])
    check_captcha = HiddenField(default='0')
    captcha = StringField('Captcha', validators=[InputRequired(), EqualTo('check_captcha', message='Captcha does not '
                                                                                                   'match')])


class FileForm(FlaskForm):
    filename_new = StringField('File Name', validators=[InputRequired(), ascii_validator])
    filename_old = HiddenField(default='filename')


class OrganizationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), ascii_validator])
    url = StringField('URL', validators=[url_ascii_validator])
    description = TextAreaField('Description', validators=[Length(max=1024), full_ascii_validator])
    image = SelectField('Image', choices=["none"], validate_choice=False)


class CertificationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(), ascii_validator])
    url = StringField('URL', validators=[url_ascii_validator])
    description = TextAreaField('Description', validators=[Length(max=1024), full_ascii_validator])
    image = SelectField('Image', choices=["none"], validate_choice=False)
    organization = SelectField('Select Organization', choices=["none"], validate_choice=False)
    cycle_length = IntegerRangeField('Cycle Length', validators=[NumberRange(min=1, max=3)])
    requirement_year = IntegerRangeField('Required each year', validators=[NumberRange(min=10, max=50)])
    requirement_full = IntegerRangeField('Required each cycle', validators=[NumberRange(min=10, max=150)])
