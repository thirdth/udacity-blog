from handlers import BlogFront
from handlers import MainPage
from handlers import EditPost
from handlers import PostPage
from handlers import NewPost
from handlers import Register
from handlers import Logout
from handlers import Login
from handlers import Welcome
from handlers import DeletePost
import webapp2


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost)
                               ],
                              debug=True)
