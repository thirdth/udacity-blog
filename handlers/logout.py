from handlers import BlogHandler
from decorators import login_required


""" LOGOUT HANDLER
Controls what happens when a User logs out of the system. It unsets the cookie
and then redirects to the 'signup' page.
"""


class Logout(BlogHandler):
    def get(self):
        self.logout()  # uses method from BlogHandler to unset cookie.
        self.redirect('/signup')
