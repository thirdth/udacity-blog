from handlers import BlogHandler
from decorators import login_required
from decorators import post_exists
from decorators import post_owner


""" EDITPOST HANDLER
Controls what happens when user tries to edit a post. It checks to make sure
the user is logged in and the called post exists, then checks to make sure
that the user is the author of the post that is to be edited. If the user is
the author, it renders the post to be edited, if not, then it reloads the blog
page with an error message.
If the User edits the blog page, then this querys the db and makes the changes
if there are any. It also allows the user to cancel editing without making
changes. If the User tries to delete the post just by emptying the contents,
user will be directed to use the 'delete post' button instead. If user chooses
to delete the post, they are redirected to the 'deletepost.html' handler.
"""


class EditPost(BlogHandler):
    # connects to the db and retrieves the current post
    @post_exists  # checks to see if the post exists
    @login_required  # confirms the user is logged in
    def get(self, post_id, Post):
        content = Post.content
        author = Post.author
        subject = Post.subject

        if self.user.name == author:
            self.render("editpost.html", author=author, subject=subject,
                        content=content, post_id=post_id)
        else:
            error = "?error=**You cannot edit this post as it is not yours."
            return self.redirect('/blog/%s%s' % (post_id, error))

    #  Controls what happens when a POST is made to the page.
    @post_owner  # confirms that the user is the author of the post
    @post_exists  # checks to see if the post exists
    @login_required
    def post(self, post_id, Post):
        # if the user has registered, user can edit the post
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.request.get('author')

        # Controls what happens when a button is clicked on the page
        # checks if user has entered info and if so, it sends to db
        if subject and content:
            if Post:  # makes sure the Post exists
                Post.subject = subject
                Post.content = content
                Post.put()
                self.redirect('/blog/%s' % str(Post.key().id()))
            else:
                error = "?error=**That post no longer exists**"
                return self.redirect('/blog/%s%s' % (str(Post.key().id()),
                                     error))
        else:  # If user clears the info, then an error message is sent.
            error = "subject and content, please! In order to delete the post,\
                    please choose the delete button below."
            self.render("editpost.html", subject=subject,
                        content=content, error=error, post_id=post_id,
                        author=author)
