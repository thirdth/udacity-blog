import re
import random
import hashlib
import hmac
from string import letters
import webapp2
from google.appengine.ext import db

secret = 'notthesameasasalt'


class Utils(webapp2.RequestHandler):
    # Methods related to creating and setting cookies.
    @staticmethod
    def make_secure_val(val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

    @staticmethod
    def check_secure_val(secure_val):
        val = secure_val.split('|')[0]
        if secure_val == Utils.make_secure_val(val):
            return val

    # Methods related to making secure passwords and logging in.
    @staticmethod
    def make_salt(length=5):
        return ''.join(random.choice(letters) for x in range(length))

    @staticmethod
    def make_pw_hash(name, pw, salt=None):
        if not salt:
            salt = Utils.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

    @staticmethod
    def valid_pw(name, password, h):
        salt = h.split(',')[0]
        return h == Utils.make_pw_hash(name, password, salt)

    @staticmethod
    def users_key(group='default'):
        return db.Key.from_path('users', group)

    # Method related to creating a parent association in the GAE database.
    @staticmethod
    def blog_key(name='default'):
        return db.Key.from_path('blogs', name)

    # Methods for use with Registration.
    @staticmethod
    def valid_username(username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return username and USER_RE.match(username)

    @staticmethod
    def valid_password(password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return password and PASS_RE.match(password)

    @staticmethod
    def valid_email(email):
        EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        return not email or EMAIL_RE.match(email)
