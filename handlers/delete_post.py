from handlers import BlogHandler
from decorators import login_required
from decorators import post_exists
from decorators import post_owner


""" DELETEPOST HANDLER
Controls what happens when 'deletepost/' is called. First it displays the
'deletepost.html' template after getting information about the post from the
database and passing that info to the browser. If a POST action is taken,
it determines whether it is a cancel action or a delete action. If cancel, then
user is sent back to edit the post. If it is a delete action, then the database
is queried and the post is deleted. User is then sent to a confirmation page.
"""


class DeletePost(BlogHandler):
    @login_required  # makes sure the user is logged in
    @post_exists  # confirms that the queried post exists
    def get(self, post_id, Post):
        content = Post.content
        author = Post.author
        subject = Post.subject
        self.render("deletepost.html", author=author, subject=subject,
                    content=content, post_id=post_id)

    # Handles what happens when a POST action is taken on the 'deletepost' page
    @post_owner  # makes sure the user is the owner of the post
    @post_exists  # confirms that the post exits
    @login_required  # makes sure the user is logged in
    def post(self, post_id, Post):
        Post.delete()
        message = "you deleted post #" + post_id
        return self.render('usermessage.html', message=message)
