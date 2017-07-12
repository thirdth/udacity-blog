import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# this tells jinja2 where to look for the templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'notthesameasasalt'

"""
A decorator to confirm a user is logged in or redirect as needed.
"""
def login_required(func):
    def login(self, *args, **kwargs):
        # Redirect to login if user is not logged in, else execute func.
        if not self.user:
            self.redirect("/login")
        else:
            func(self, *args, **kwargs)
    return login


"""
Class of helper methods that are used throughout the code.
"""
class Utils(webapp2.RequestHandler):
    @staticmethod
    def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

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


"""
Databases
"""


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=Utils.users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = Utils.make_pw_hash(name, pw)
        return cls(parent=Utils.users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and Utils.valid_pw(name, pw, u.pw_hash):
            return u


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
        return Utils.render_str("post.html", p=self)


# Creates the Comment database
class Comment(db.Model):
    author = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Creates the Likes database
class Likes(db.Model):
    post_id = db.IntegerProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


""" MAIN HANDLER
The following are the handlers for this blog website.
"""


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return Utils.render_str(template, **params)

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


"""
MAINPAGE, WELCOME, and BLOGFRONT HANDLERS.
"""


# Handler redirects User from / to /blog on the website.
class MainPage(BlogHandler):
    def get(self):
        self.redirect('/blog')


# Controls what happens at the /blog page
class BlogFront(BlogHandler):
    def get(self):  # all posts are rendered on this page.
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)  # passes 'posts' to front.html


# Once user is signed in, user is redirected to 'welcome.html'
class Welcome(BlogHandler):
    def get(self):
        if self.user:  # all users posts are rendered on welcome page.
            posts = Post.all().order('-created')
            self.render('welcome.html', username=self.user.name, posts=posts)
        else:  # if user not signed in, then redirected to 'signup' page.
            self.redirect('/signup')


""" POSTPAGE HANDLER
This is the handler for the single post page. It confirms that the user is
logged in, and then confirms that there is a post, determines whether the user
has liked this post already, and then renders the 'permalink.html' template on
the page.
"""


class PostPage(BlogHandler):
    @login_required
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
        post = db.get(key)
        name = self.user.name
        comment = Comment.all().order('-created')
        likes = Likes.all()
        error = self.request.get('error')

        if not post: # checks for the existence of the post, or returns error
            self.error(404)
            return
        # Sees if the user has already liked this post.
        count = 0
        likeid = False
        if likes:
            for l in likes:
                if l.post_id == int(post_id):
                    count += 1
                    if l.author == name:
                        likeid = True
        # Renders 'permalink.html' and passes the following variables to it.
        self.render("permalink.html", post=post, name=name,
                    post_id=int(post_id), comment=comment,
                    likeid=likeid, count=count, error=error)

    """
    Controls what happens when a POST is made on the page. It checks to see iF
    POST was a 'like' an 'unlike' or 'comment'. It then reloads the page based
    on that selection, with the new information.
    """
    def post(self, post_id):
        comment = self.request.get('comment')
        author = self.user.name
        likes = self.request.get('likes')
        post_id = int(post_id)
        unlikes = self.request.get('unlikes')
        error = ""
        liked = Likes.all()
        likeId = False
        if liked:
            for l in liked:
                if l.post_id == post_id:
                    if l.author == author:
                        likeId = True

    # Likes & Unlikes
        # This code is run if the "like" button is clicked
        if likes:  # makes sure user can't like own page, or like page twice
            if likes != author and not likeId:
                l = Likes(parent=Utils.blog_key(), author=author,
                          post_id=post_id)
                l.put()
                self.redirect('/blog/%s' % post_id)

            else:
                if likes == author:
                    error = "?error=**You can't like your own post.**"
                else:
                    error = "?error=**You have already liked this post."

        # Query the Likes db, filters to current user/current post and deletes
        if unlikes:
            likes = Likes.all().order('-created')
            for l in likes:
                if l.post_id == post_id:
                    if l.author == author:
                        l.delete()

    # comments
        # connects to GAE db and puts the comment in the db if a comment exists
        if comment:
            c = Comment(parent=Utils.blog_key(), comment=comment,
                        author=author, post_id=post_id)
            c.put()
            self.redirect('/blog/%s%s' % (post_id, error))
        else:  # if no comment exists, then the page is simply reloaded
            self.redirect('/blog/%s%s' % (post_id, error))


""" NEWPOST HANDLER
Controls what happens on the newpost page. Renders the 'newpost.html' template,
then if a POST is made, it checks to make sure that there is subject and
content, if there is, it sends that information to the Post db, if not, then
it reloads the page with an error message.
"""


class NewPost(BlogHandler):
    @login_required
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent=Utils.blog_key(), subject=subject, content=content,
                     author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error,)


""" EDITPOST HANDLER
Controls what happens when user tries to edit a post. It checks to make sure
the user is logged in, then checks to make sure that the user is the author
of the post that is to be edited. If the user is the author, it renders the
post to be edited, if not, then it reloads the blog page with an error message.
If the User edits the blog page, then this querys the db and makes the changes
if there are any. It also allows the user to cancel editing without making
changes. If the User tries to delete the post just by emptying the contents,
user will be directed to use the 'delete post' button instead. If user chooses
to delete the post, they are redirected to the 'deletepost.html' handler.
"""


class EditPost(BlogHandler):
    # connects to the db and retrieves the current post
    @login_required
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
        query = db.get(key)
        content = query.content
        author = query.author
        subject = query.subject

        if self.user.name == author:
            self.render("editpost.html", author=author, subject=subject,
                        content=content, key=key, post_id=post_id)
        else:
            error = "?error=**You cannot edit this post as it is not yours."
            return self.redirect('/blog/%s%s' % (post_id, error))

    """
    Controls what happens when a POST is made to the page.
    """
    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        # if the user has registered, user can edit the post
        key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')
        post_id = post_id
        go = self.request.get('go')

        # Controls what happens when a button is clicked on the page
        if go == "cancel":  # Cancel reloads the blog post.
            self.redirect('/blog/%s' % post_id)

        elif go == "delete":  # Delete redirects user to 'deletepost.html'
            self.redirect("/deletepost.html")
        else:
            # checks if user has entered info and if so, it sends to db
            if subject and content:
                Post = db.get(key)
                if Post is not None:  # makes sure the Post exists
                    Post.subject = subject
                    Post.content = content
                    Post.put()
                    self.redirect('/blog/%s' % str(Post.key().id()))
                else:
                    error = "?error=**That post no longer exists**"
                    return self.redirect('/blog/%s%s' % (str(Post.key().id()),
                                         error))
            else: # If user clears the info, then an error message is sent.
                error = "subject and content, please! In order to delete the post,\
                        please choose the delete button below."
                self.render("editpost.html", subject=subject,
                            content=content, error=error, post_id=post_id,
                            author=author)


""" DELETEPOST HANDLER
Controls what happens when 'deletepost/' is called. First it displays the
'deletepost.html' template after getting information about the post from the
database and passing that info to the browser. If a POST action is taken,
it determines whether it is a cancel action or a delete action. If cancel, then
user is sent back to edit the post. If it is a delete action, then the database
is queried and the post is deleted. User is then sent to a confirmation page.
"""


class DeletePost(BlogHandler):
    @login_required
    def get(self, post_id):
        # queries the db to re-render the page for confirmation
        key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
        query = db.get(key)
        content = query.content
        author = query.author
        subject = query.subject
        self.render("deletepost.html", author=author, subject=subject,
                    content=content, key=key, post_id=post_id)

    # Handles what happens when a POST action is taken on the 'deletepost' page
    def post(self, post_id):
        go = self.request.get('go')
        post_id = self.request.get('post_id')
        user = self.user.name
        if go == "cancel":  # Cancel button sends user back to editpost.
            self.redirect('/blog/editpost/%s' % str(post_id))

        # queries db for proper post, deletes and send to confirmation page
        else:
            key = db.Key.from_path('Post', int(post_id), parent=Utils.blog_key())
            post = db.get(key)
            # confirms the user is the post author
            if post.author == user:
                post.delete()
                message = "you deleted post #" + post_id
                self.render('usermessage.html', message=message)
            else:  # error message if user is not post author
                error = "?error=**I don't know how you got here, but you can't\
                delete someone else's post."
                return self.redirect('/blog/%s%s' % (post_id, error))


#  login and registration
#  username and password verification
#  TODO: better verification processes needed for production site


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


""" LOGOUT HANDLER
Controls what happens when a User logs out of the system. It unsets the cookie
and then redirects to the 'signup' page.
"""


class Logout(BlogHandler):
    def get(self):
        self.logout()  # uses method from BlogHandler to unset cookie.
        self.redirect('/signup')


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
