from handlers import BlogHandler
from decorators import login_required
from models import User


""" LOGIN HANDLER
Controls what happens on the 'login' page. Initially, it renders the
'login-form.html' template. If a POST action is taken, then it checks the info
against the User db and confirms the info is correct. If it is, then it sends
the user to the welcome page, if not, then it re-renders the page with an
error message.
"""


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        """
        Utilizing the User class, this puts the corresponding user info into
        the variable if it exists.
        """
        u = User.login(username, password)
        if u:
            self.logcookie(u)
            self.redirect('/welcome')
        else:  # if the variable is empty, then username and pw are incorrect
            msg = '* Please try again *'
            self.render('login-form.html', error=msg)
