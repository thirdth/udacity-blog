from handlers import BlogHandler


# Handler redirects User from / to /blog on the website.
class MainPage(BlogHandler):
    def get(self):
        self.redirect('/blog')
