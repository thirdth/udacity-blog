from handlers import BlogHandler
from Utils import Utils
from models import User


""" REGISTER HANDLER
Controls the actions of the registration page. Initially renders the
'signup-form.html' template. If a POST action is taken, then it verifies the
information. If the information is not verified, then it re-renders the page
with an error message. If the info is good, then it runs the 'done()' method.
That method checks to make sure there are no duplicate user names, if there are
then the page re-renders with an error message. If not, then it puts the info
into the User db and sends the user to the /blog page while setting a cookie.
"""


class Register(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # validity checks using functions from Utils class
        if not Utils.valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not Utils.valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not Utils.valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self):
        # queries db to make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.logcookie(u)
            self.redirect('/blog')
