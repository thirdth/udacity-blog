# Multi-user blog
Source code for a multi-user blog website. This code was created as a project
for **Full Stack Web Developer Nanodegree Program** from **Udacity**

## Usage instructions:
#### Running through GAE:
1. This program is intended to be used with Google App Engine.
2. It can be accessed [here](https://udacity-blog-glaser.appspot.com/blog)
3. The user may read the blog website without registering, but the user will need to register in order to create posts, or interact with posts that have already been created.

#### Running independently of GAE:
1. If the user would like to run the program independently of Google App Engine, he or she will need to download the Google Cloud SDK Shell which can be found [here](https://cloud.google.com/sdk/downloads)
2. Once the user has downloaded the GC SDK Shell, user will need to navigate to the folder that contains the program files.
3. Once at the proper folder, user needs to enter `dev_appserver app.yaml` into the shell.
4. User will then need to navigate to `http://localhost:8080/blog` in user's browser.
5. This will create a locally run version of the program.
6. When user is done with the program, focus on the GC SDK Shell and hit `ctrl + C` to close the localhost connection.


## Known Issues:
1. Posts are allowed to use html in order to allow for better quality posts. User is advised to use HTML with caution.
