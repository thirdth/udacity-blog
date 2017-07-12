from handlers import BlogHandler
from models import Post


# Once user is signed in, user is redirected to 'welcome.html'
class Welcome(BlogHandler):
    def get(self):
        if self.user:  # all users posts are rendered on welcome page.
            posts = Post.all().order('-created')
            self.render('welcome.html', username=self.user.name, posts=posts)
        else:  # if user not signed in, then redirected to 'signup' page.
            self.redirect('/signup')
