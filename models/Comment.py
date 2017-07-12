from google.appengine.ext import db


# Creates the Comment database
class Comment(db.Model):
    author = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
