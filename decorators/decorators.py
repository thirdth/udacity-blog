from google.appengine.ext import db
from Utils import Utils


#  A decorator to confirm a user is logged in or redirect as needed.
def login_required(func):
    def login(self, *args, **kwargs):
        # Redirect to login if user is not logged in, else execute func.
        if not self.user:
            return self.redirect("/login")
        else:
            return func(self, *args, **kwargs)
    return login


# Checks to make sure that a post exists
def post_exists(func):
    def post_check(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
        Post = db.get(key)
        if Post:
            return func(self, post_id, Post)
        else:
            error = "That post does not exist in the database."
            return self.render('usermessage.html', message=error)
    return post_check


def post_owner(func):
    def wrapper(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
        Post = db.get(key)
        currentuser = self.user.name
        author = Post.author

        if currentuser == author:
            return func(self, post_id)
        else:
            error = "You cannot edit or delete someone else's post."
            return self.render('editpost.html', error=error)
    return wrapper
