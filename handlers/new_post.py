from handlers import BlogHandler
from models import Post
from decorators import login_required
from Utils import Utils


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

    @login_required
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
