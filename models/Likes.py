from google.appengine.ext import db


# Creates the Likes database
class Likes(db.Model):
    post_id = db.IntegerProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
