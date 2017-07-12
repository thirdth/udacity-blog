import webapp2
import jinja_utils
from Utils import Utils
from models import User


secret = 'notthesameasasalt'


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return jinja_utils.render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# Methods related to creating cookies and logging in and out.
    def set_secure_cookie(self, name, val):
        cookie_val = Utils.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and Utils.check_secure_val(cookie_val)

    def logcookie(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
