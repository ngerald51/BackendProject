import os
import re
import random
import hashlib
import hmac
from string import letters
import time

import webapp2
import jinja2

from google.appengine.ext import db

""" Things to work on
Users should only be able to like posts once
 and should not be able to like their own post.
"""

# Import Jinja Template which will later be use to embed within html
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
secret = 'fart'


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

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Reading COOKIE
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# user related functions
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


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
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog related operations

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class commentDB(db.Model):
    # Create table for comments
    comment = db.StringProperty(required=False)
    id = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    usernameid = db.StringProperty(required=False)
    postid = db.StringProperty(required=False)
    desiUser = db.StringProperty(required=False)
    destSubject = db.StringProperty(required=False)
    likeChecker = db.StringProperty(required=False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p=self)


class Post(db.Model):
    # Create table for Post
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):

    def get(self):
        # show post of all other users but not of self
        if self.request.get('opost') and self.user:
            # posts = Post.all().order('-created')
            posts = db.GqlQuery("select * from Post where "
                                "author !='%s';" % self.user.name)
            opost = self.request.get('opost')

            # use opost parameter to determine user is views own post.
            self.render('front.html', posts=posts,
                        opost=opost, users1=self.user.name)

        # Initial launch of this website, sql query to display user own items.
        elif self.user:
            posts = db.GqlQuery("select * from Post where"
                                " author ='%s';" % self.user.name)
            self.render('front.html', posts=posts)

        else:
            return self.redirect("/login")


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post',
                               int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class EditPost(BlogHandler):
    def get(self, post_id):

        if self.user and self.request.get('comment'):
            # Edit Comments page.
            key = db.Key.from_path('commentDB',
                                   int(post_id), parent=blog_key())
            comments = db.get(key)
            self.render("editcomment.html", comments=comments)
        elif self.user:
            # Edit Post Page
            key = db.Key.from_path('Post',
                                   int(post_id), parent=blog_key())
            post = db.get(key)
            self.render("editpost.html", post=post)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        if self.user and self.request.get('comment'):
            key = db.Key.from_path('commentDB',
                                   int(post_id), parent=blog_key())
            posts = db.get(key)
            # check authoer is also same user to amend post.
            if self.user.name != posts.usernameid:
                return self.redirect("/blog")

            posts.comment = self.request.get('comments')
            posts.put()
            time.sleep(1)
            return self.redirect("/usercomment")

        elif self.user:
            key = db.Key.from_path('Post',
                                   int(post_id), parent=blog_key())
            posts = db.get(key)
            if self.user.name != posts.author:
                return self.redirect("/blog")
            posts.content = self.request.get('content')
            posts.subject = self.request.get('subject')
            posts.put()
            time.sleep(1)
            return self.redirect("/blog")
        else:
            return self.redirect("/login")


class userComments(BlogHandler):
    # Select only comments Author have made to others.
    def get(self):
        comments = db.GqlQuery("select * from commentDB where usernameid='%s' "
                               "order by last_modified desc;" % self.user.name)

        if self.user:
            self.render("usercomment.html", comments=comments)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        if self.user:
            comments = db.GqlQuery("select * from commentDB where"
                                   " postid='%s' order by last_modified desc;"
                                   % post_id)
            comments.comment = self.request.get('comment')

            if self.user.name != comments.usernameid:
                return self.redirect('/blog/')

            comments.put()
            time.sleep(1)
            return self.redirect("/blog/usercomment")
        else:
            return self.redirect("/login")


class Delete(BlogHandler):
    """
    Handler that deletes  posts.
    Get id and delete those post.
    Timer use to ensure page refresh and reflect info appropriately
    """

    def post(self, id):

        if not self.user:
            return self.redirect('/login')

        if self.request.get('comment'):
            key = db.Key.from_path('commentDB',
                                   int(id), parent=blog_key())
            link = "/usercomment"
        else:
            key = db.Key.from_path('Post',
                                   int(id), parent=blog_key())
            link = "/blog/"

        post = db.get(key)

        if link == "/usercomment":
            userid = post.usernameid
        else:
            userid = post.author

        if self.user.name != userid:
            return self.redirect('/blog/')

        post.delete()
        time.sleep(1)
        return self.redirect(link)

    def get(self, id):
        if not self.user:
            return self.redirect('/login')

        if self.request.get('comment'):
            key = db.Key.from_path('commentDB',
                                   int(id), parent=blog_key())
            link = "/usercomment"
        else:
            key = db.Key.from_path('Post',
                                   int(id), parent=blog_key())
            link = "/blog/"
        post = db.get(key)

        if link == "/usercomment":
            userid = post.usernameid
        else:
            userid = post.author

        if self.user.name != userid:
            return self.redirect('/blog/')

        post.delete()
        time.sleep(1)
        return self.redirect(link)


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        # Form Validation for signup page.

        if subject and content:
            p = Post(parent=blog_key(),
                     subject=subject, content=content, author=author)
            if self.user.name != p.author:
                return self.redirect("/blog")

            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
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

        # Form Validations for signup page
        if not valid_username(self.username):
            params[
                'error_username'] = "That's not a valid username." \
                                    " Please ensure your username" \
                                    " is at least 5 characters"
            have_error = True

        if not valid_password(self.password):
            params[
                'error_password'] = "That wasn't a valid password." \
                                    " Please ensure your username " \
                                    "is at least 5 characters"
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

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            return self.redirect('/blog')


# Class to redirect users from editing other people's post
class Comment(BlogHandler):

    def get(self):
        self.render('welcome.html')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login, please check either username or password!'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.render('Logout.html', username=self.user.name)


class CommentHandler(BlogHandler):
    # Handler that handles existing comments.

    def get(self, post_id):

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery("select * from commentDB where"
                               " postid='%s' order by last_modified desc;"
                               % post_id)

        likeChecker = db.GqlQuery("select * from commentDB where postid='%s' "
                                  "and usernameid='%s' and likeChecker='on';"
                                  % (post_id, self.user.name))
        if likeChecker.count(10) > 1:
            like = "on"
        else:
            like = ""

        if self.user:
            self.render("comment.html", post=post,
                        comments=comments, likeChecker=like)
        else:
            return self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        comment = self.request.get('comment')
        destUser = self.request.get('desiUser')
        destSubject = self.request.get('destSubject')
        likeChecker = self.request.get('likeChecker')
        # Form Validation to ensure user has entered comments.
        # PARSE comments, username, post id, Sender Name, Subject
        if comment:
            p = commentDB(parent=blog_key(), comment=comment,
                          usernameid=self.user.name, postid=post_id,
                          desiUser=destUser, destSubject=destSubject,
                          likeChecker=likeChecker)

            # check whether current author is also signed in user.
            if self.user.name != p.usernameid:
                return self.redirect("/blog")
            p.put()
            return self.redirect('/comment/%s' % post_id)
        else:
            error = "Please write a comment"
            self.render("comment.html", post=1, error=error)

app = webapp2.WSGIApplication([('/', Login),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/editpost/([0-9]+)/?', EditPost),
                               ('/logout', Logout),
                               ('/usercomment', userComments),
                               ('/blog/delete/([0-9]+)', Delete),  # Del Post
                               ('/blog/delete/([0-9]+)/?', Delete),  # Del Comments
                               # Redirect to Comment page.
                               ('/comment/([0-9]+)', CommentHandler),
                               # Redirect to warning page.
                               ('/comment/', Comment)],
                              debug=True)
