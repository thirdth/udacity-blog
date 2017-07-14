from google.appengine.ext import db
from models import User
import jinja_utils


# Creates the Post database
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=False)

    """
    Method renders the post.html file and passes the 'p' parameter, and places
    the line breaks in between each post.
    """
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return jinja_utils.render_str("post.html", p=self)
