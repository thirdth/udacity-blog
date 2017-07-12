from handlers import BlogHandler
from models import Post


# Controls what happens at the /blog page
class BlogFront(BlogHandler):
    def get(self):  # all posts are rendered on this page.
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)  # passes 'posts' to front.html
