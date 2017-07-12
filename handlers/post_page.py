from handlers import BlogHandler
from Utils import Utils
from decorators import login_required
from decorators import post_exists
from models import Comment
from models import Likes


""" POSTPAGE HANDLER
This is the handler for the single post page. It confirms that the user is
logged in, and then confirms that there is a post, determines whether the user
has liked this post already, and then renders the 'permalink.html' template on
the page.
"""


class PostPage(BlogHandler):
    @post_exists
    @login_required
    def get(self, post_id, Post):
        name = self.user.name
        comment = Comment.all().order('-created')
        likes = Likes.all()
        error = self.request.get('error')

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
        self.render("permalink.html", post=Post, name=name,
                    post_id=int(post_id), comment=comment,
                    likeid=likeid, count=count, error=error)

    """
    Controls what happens when a POST is made on the page. It checks to see iF
    POST was a 'like' an 'unlike' or 'comment'. It then reloads the page based
    on that selection, with the new information.
    """
    @post_exists
    @login_required
    def post(self, post_id, Post):
        comment = self.request.get('comment')
        author = self.user.name
        likes = self.request.get('likes')
        unlikes = self.request.get('unlikes')
        error = ""
        liked = Likes.all()
        haveliked = False
        if liked:
            for l in liked:
                if l.post_id == int(post_id):
                    if l.author == author:
                        haveliked = True

    # Likes & Unlikes
        # This code is run if the "like" button is clicked
        if likes:  # makes sure user can't like own page, or like page twice
            if likes != author and not haveliked:
                l = Likes(parent=Utils.blog_key(), author=author,
                          post_id=int(post_id))
                l.put()
                self.redirect('/blog/%s' % post_id)

            else:
                if likes == author:
                    error = "?error=**You can't like your own post.**"
                    return self.redirect('/blog/%s%s' % (post_id, error))
                else:
                    error = "?error=**You have already liked this post."
                    return self.redirect('/blog/%s%s' % (post_id, error))

        # Query the Likes db, filters to current user/current post and deletes
        if unlikes:
            likes = Likes.all().order('-created')
            for l in likes:
                if l.post_id == int(post_id):  # shuffles to proper post
                    if l.author == author:  # confirm user is one who liked
                        l.delete()
                else:
                    error = '?error=You have not liked anything'
                    return self.redirect('/blog/%s%s%s%s' % (post_id, error))

    # comments
        # connects to GAE db and puts the comment in the db if a comment exists
        if comment:
            if self.user:
                c = Comment(parent=Utils.blog_key(), comment=comment,
                            author=author, post_id=int(post_id))
                c.put()
                self.redirect('/blog/%s%s' % (post_id, error))
            else:
                error = "?error=You must be logged in to comment"
                return self.redirect('/blog/%s%s' % (post_id, error))
        else:  # if no comment exists, then the page is simply reloaded
            return self.redirect('/blog/%s' % post_id)
