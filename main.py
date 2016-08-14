import os
import webapp2
import jinja2
import re
import random
import hashlib
import hmac
import json
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'aigjaisjgalpkb;adofkgqot['';912adfds5hrt81-'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


### functions to generate and check hashcode for username, password, cookie...
def make_secure_val(val):
    h = hmac.new(secret, val).hexdigest()
    return '%s|%s' % (val, h)

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


### User class definition, find user by ID or username, register, and login.
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

## User as the database name
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    ## the database operation below, such as User.get_by_id, User.all can be substituted 
    ## by standard database operation such as db.GqlQuery('select * from User where ...')

    ## find user by id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    ## find user by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    ## register, create a new user with its name, password (by hashcode), email, return user
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(), name = name, pw_hash = pw_hash, email = email)

    ## login, if user exists and the password is valid return the user data
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



## BlogHandler with basic webpage event. render page. read/set cookies, login/logout to set cookies.
## All other classes below will inherit BlogHandler.

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)  # contains userid and hash
        return cookie_val and check_secure_val(cookie_val)

    def login_toSetCookie(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout_toClearCookie(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
        	self.format = 'json'
        else:
        	self.format = 'html'


### MainPage for test
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, there!')



### User functions: signup, login, logout. All inherit BlogHandler.

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


## Signup. 
class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

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
            #self.redirect('/blog/welcome?username=' + username)

    def done(self, *a, **kw):
        raise NotImplementedError

## TestRegister. This is signup/register page for test
class TestRegister(Signup):
    def done(self):
        self.redirect('/welcome?username=' + self.username)

## actual Register. This is the actual register for the blog, where a user will be created and added to database User.
class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login_toSetCookie(u)
            self.redirect('/blog')

## Login. Check if username/pw are valid.
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login_toSetCookie(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

## Logout. Clear the cookie, and go to the front page.
class Logout(BlogHandler):
    def get(self):
        self.logout_toClearCookie()
        self.redirect('/blog')



## Welcome page for test.
class TestWelcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/signup')

## actual welcome page for blog. If username is valid go to welcome page, else (including empty username) go to signup.
class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/blog/signup')


### real blog part: post, front page, permalink

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def toDict(self):
    	time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d


## show either html version of json version
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        #posts = db.GqlQuery("select * from Post order by created desc limit 10")
        if self.format == "html":
        	self.render('front.html', posts = posts)
        else:
        	json_dict = [post.toDict() for post in posts]
        	self.render_json(json_dict)

## show either html version of json version
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        #post = Post.get_by_id(post_id)

        if not post:
            self.error(404)
            return

        if self.format == "html":
        	self.render("permalink.html", post = post)
        else:
        	self.render_json(post.toDict())

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()

            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Please enter both subject and content and try again."
            self.render("newpost.html", subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/welcome', TestWelcome),
                               ('/signup', TestRegister),
                               ('/blog/welcome', Welcome),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/?(?:\.json)?', BlogFront),
                               ('/blog/([0-9]+)(?:\.json)?', PostPage),
                               ('/blog/newpost', NewPost)
                               ],
                              debug=True)
