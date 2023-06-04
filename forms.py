from flask_wtf import FlaskForm  # integration with WTForms, data validation and CSRF protection
from flask_wtf.file import FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, HiddenField, FileField, TextAreaField, SelectField, IntegerField, DateField
from wtforms.validators import InputRequired, NoneOf, EqualTo, Email, Length, NumberRange, DataRequired


# Every form used both in the Flask/Jinja templates as well the main Python app is defined here.
# Not all fields have full validators as they are used in modal windows.

class LoginForm(FlaskForm):
    student = StringField('Name', validators=[InputRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=20)])
    remember = BooleanField('Remember me', default='checked')


class PasswordForm(FlaskForm):
    email = StringField('E-Mail', validators=[InputRequired(), Email()])


class PasswordResetForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=5, max=20)])


class AccountForm(FlaskForm):
    student = StringField('Name', validators=[InputRequired(), Length(min=5, max=20),
                                              NoneOf([' '], message='No spaces allowed')])
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=5, max=20)])
    invitation = StringField('Invitation Code', validators=[InputRequired(), Length(min=5, max=20)], default='guest')


class MailStudentForm(FlaskForm):
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    description = TextAreaField('Description', validators=[Length(max=1024)])
    image = SelectField('Image', choices=["none"], validate_choice=False)
    notification = BooleanField('Send notifications', default='checked')


class PassStudentForm(FlaskForm):
    password = PasswordField('Password', validators=[InputRequired(), Length(min=5, max=20),
                                                     EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('Password Verification', validators=[InputRequired(), Length(min=5, max=20)])
    operation = HiddenField(default='pass')


class DelStudentForm(FlaskForm):
    operation = HiddenField(default='delete')


class UploadForm(FlaskForm):
    file = FileField(validators=[FileRequired(), FileAllowed(['jpg', 'png', 'gif'], 'Images only!')])


class ContactForm(FlaskForm):
    contact_name = StringField('Name', validators=[InputRequired(), Length(min=5, max=20)])
    email = StringField('E-Mail', validators=[InputRequired(), Email()])
    message = TextAreaField('Message', validators=[Length(max=1024)])
    check_captcha = HiddenField(default='0')
    captcha = StringField('Captcha', validators=[InputRequired(), EqualTo('check_captcha', message='Captcha does not '
                                                                                                   'match')])


class FileForm(FlaskForm):
    filename_new = StringField('File Name', validators=[InputRequired()])
    filename_old = HiddenField(default='filename')


class OrganizationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    url = StringField('URL')
    description = TextAreaField('Description')
    image = SelectField('Image', choices=["none"], validate_choice=False)


class CertificationForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    url = StringField('URL')
    description = TextAreaField('Description')
    image = SelectField('Image', choices=["none"], validate_choice=False)
    organization = SelectField('Select Organization', choices=["none"], validate_choice=False)
    certification_date = DateField('Certification Date', format='%Y-%m-%d', validators=[DataRequired()])
    cycle_length = IntegerField('Cycle Length', validators=[InputRequired(), NumberRange(min=1, max=5)])
    cycle_start = DateField('Certification Date', format='%Y-%m-%d', validators=[DataRequired()])
    requirement_year = IntegerField('Required each year', validators=[InputRequired(), NumberRange(min=1, max=50)])
    requirement_full = IntegerField('Required each cycle', validators=[InputRequired(), NumberRange(min=1, max=250)])
