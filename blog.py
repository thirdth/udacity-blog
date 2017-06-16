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


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# Cookies and Login stuff
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def logcookie(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content + '<br>')


class MainPage(BlogHandler):
    def get(self):
        self.redirect('/blog')


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in range(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# creating database entities in GAE
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    author = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class Likes(db.Model):
    post_id = db.IntegerProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


# handlers
# handler for Frontpage
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


# handler for the single-post page
class PostPage(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            name = self.user.name
            comment = Comment.all().order('-created')
            likes = Likes.all()
            error = self.request.get('error')

            if not post:
                self.error(404)
                return

            count = 0
            likeid = False
            if likes:
                for l in likes:
                    if l.post_id == int(post_id):
                        count += 1
                        if l.author == name:
                            likeid = True
            self.render("permalink.html", post=post, name=name,
                        post_id=int(post_id), comment=comment,
                        likeid=likeid, count=count, error=error)
        else:
            self.redirect("/login")

# Controls happens when you submit a form on the single-post page
    def post(self, post_id):
        comment = self.request.get('comment')
        author = self.user.name
        likes = self.request.get('likes')
        post_id = int(post_id)
        unlikes = self.request.get('unlikes')
        error = ""

# Likes & Unlikes
# This code is run if the "like" button is clicked
        if likes:
            if likes != author:  # Makes sure user cannot like his/her own page
                l = Likes(parent=blog_key(), author=author, post_id=post_id)
                l.put()
                self.redirect('/blog/%s' % post_id)
            else:
                error = "?error=**You can't like your own post.**"

# Queries the Likes db, filters to current user with current post and deletes
        if unlikes:
            likes = Likes.all().order('-created')
            for l in likes:
                if l.post_id == post_id:
                    if l.author == author:
                        l.delete()

# comments
# connects to GAE db and puts the comment in the db if a comment exists
        if comment:
            c = Comment(parent=blog_key(), comment=comment, author=author,
                        post_id=post_id)
            c.put()
            self.redirect('/blog/%s%s' % (post_id, error))
        else:
            self.redirect('/blog/%s%s' % (post_id, error))


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error,)


# handler for editing the posts
class EditPost(BlogHandler):
    # connects to the db and retrieves the current post
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            query = db.get(key)
            content = query.content
            author = query.author
            subject = query.subject
            self.render("editpost.html", author=author, subject=subject,
                        content=content, key=key, post_id=post_id)
        else:
            self.redirect('/login')

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
# if the user has registered, user can edit the post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')
        post_id = post_id
        go = self.request.get('go')

        if go == "cancel":
            self.redirect('/blog/%s' % post_id)

        elif go == "delete":
            self.redirect("/deletepost.html")
        else:
            # checks if user has entered info and if so, it sends to db
            if subject and content:
                Post = db.get(key)
                Post.subject = subject
                Post.content = content
                Post.put()
                self.redirect('/blog/%s' % str(Post.key().id()))
            else:
                error = "subject and content, please! In order to delete the post,\
                        please choose the delete button below."
                self.render("editpost.html", subject=subject,
                            content=content, error=error, post_id=post_id,
                            author=author)


# handler for deleted posts
class DeletePost(BlogHandler):
    def get(self, post_id):
        # queries the db to re-render the page for confirmation
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        query = db.get(key)
        content = query.content
        author = query.author
        subject = query.subject
        self.render("deletepost.html", author=author, subject=subject,
                    content=content, key=key, post_id=post_id)

    def post(self, post_id):
        go = self.request.get('go')
        post_id = self.request.get('post_id')
        if go == "cancel":
            self.redirect('/blog/editpost/%s' % str(post_id))

        # queries db for proper post, deletes and send to confirmation page
        else:
            post = Post.all()
            for p in post:
                if int(p.key().id()) == int(post_id):
                    p.delete()
                    message = "you deleted post #" + post_id
                    self.render('usermessage.html', message=message)


#  login and registration
#  username and password verification
#  TODO: better verification processes needed for production site
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# handler for signup page
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

        # validity checks using functions from above
        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
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


# handler for login page
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.logcookie(u)
            self.redirect('/welcome')
        else:
            msg = '* Please try again *'
            self.render('login-form.html', error=msg)


# handler for logout page
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')


# handler for welcome page
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            posts = Post.all().order('-created')
            self.render('welcome.html', username=self.user.name, posts=posts)
        else:
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
