# os funcs and regex
import os
import re

# minimal web frameworks
import webapp2
import jinja2

# hashing libs for cookies && passowrds
import hmac
import hashlib
import random
from string import letters

# google datastore
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


class Valid():
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    @classmethod
    def username(cls, username):
        return USER_RE.match(username)

    @classmethod
    def password(cls, password):
        return PASS_RE.match(password)

    @classmethod
    def email(cls, email):
        return (EMAIL_RE.match(email) or email == '')

    @classmethod
    def verifyCmp(cls, password, verify):
        return password == verify


class Hash():
    cookieSecret = "FsdKJSD843(*#$jk2n)!weeh3"

    @classmethod
    def __gen(self, algo, *algoParams):
        # hashlib.sha256("name+pw+salt").hexdigest()
        # hmac.new(secret, val).hexdigest()
        return algo(*algoParams).hexdigest()

    @classmethod
    def __genSalt(self, length=5):
        return ''.join(random.choice(letters) for x in xrange(length))

    @classmethod
    def cookie(cls, val):
        h = cls.__gen(hmac.new, cls.cookieSecret, val)
        return '{value}|{hash}'.format(value=val, hash=h)

    @classmethod
    def password(cls, username, pwd, salt=''):
        if not salt:
            salt = cls.__genSalt()

        print ""
        print ""
        print ""
        print "PWD:" + pwd
        print "SALT:" + salt
        print username
        print ""
        print ""
        print ""
        h = cls.__gen(hashlib.sha256, username + pwd + salt)
        return '{value}|{salt}'.format(value=h, salt=salt)


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Cookie():

    @classmethod
    def get(cls, caller, name, defaultVal=''):
        c = caller.request.cookies.get(name, defaultVal)
        if not c:
            return defaultVal
        plainVal = c.split('|')[0]
        # validate cookie
        if(Hash.cookie(plainVal) == c):
            return plainVal

    @classmethod
    def set(cls, caller, name, val, path='/'):
        # hash value before setting unless its empty
        # if empty do not hash
        secureVal = ''
        if(val):
            secureVal = Hash.cookie(val)

        cookie = '{name}={val}; Path={path}'.format(
            name=name, val=secureVal, path=path)
        caller.response.headers.add_header('Set-Cookie', cookie)

    @classmethod
    def clear(cls, caller, name, path='/'):
        cls.set(caller, name, '', path)

# helper class for auto hashing passwords on input
# class HashedPwProperty(db.TextProperty):
#
#    __username = ''
#
#    def __init__(self, username='', **kwargs):
#        super(HashedPwProperty, self).__init__(**kwargs)
#        self.__username = username
#
#    def hashPw(self, pw):
#        if self.__username:
#            return Hash.password(self.__username, pw)
#        else:
#            raise ValueError('username cannot be empty!')
#
#    def get_value_for_datastore(self, model_instance):
#        result = super(HashedPwProperty, self).get_value_for_datastore(
#            model_instance)
#        result = self.hashPw(result)
#        return db.Text(result)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    lastModified = db.DateTimeProperty(auto_now=True)
    # array of names that liked this post
    likes = db.TextProperty()
    # will be array of Posts
    #comments = db.TextProperty()


class User(db.Model):

    # array of post ID's
    associatedPosts = db.TextProperty()
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def login(cls, name, password):
        curUsr = cls.getByName(name)
        # check if username exists
        if not curUsr:
            return False
        # split the salt and hashed pw from the user obj
        hashedPwArr = curUsr.password.split('|')
        hashPw = hashedPwArr[0]
        salt = hashedPwArr[1]
        inputtedPass = Hash.password(name, password, salt).split('|')[0]
        print hashPw
        print inputtedPass
        # check if hashedPw matches with users inputted pw
        return hashPw == inputtedPass

    @classmethod
    def getByName(cls, name):

        # get the user object
        queryString = "WHERE name = '{name}'".format(name=name)

        # get first entry
        return User.gql(queryString).get()

    @classmethod
    def getById(cls, uid):
        return cls.get_by_id(int(uid)).get()

    @classmethod
    def register(cls, name, password, email=''):
        # check if name exists
        if cls.getByName(name):
            return None
        password = Hash.password(name, password)
        user = User(name=name, password=password, email=email, username=name)
        user.put()
        return user


class Signup(Handler):

    def get(self):
        return


class front(Handler):

    def get(self):
        #curUser = User.register("test", "bueno")
        # print curUser.name
        # print curUser.password
        print "testing user"
        curUser = User.getByName('test')

        print curUser.key().id()
        nxtUsr = User.get_by_id(curUser.key().id())
        print nxtUsr.password
        print User.login('tet', 'bueno')
        usrCookie = Cookie.get(self, 'currUsr')
        print usrCookie
        Cookie.set(self, 'currUsr', curUser.name)
        usrCookie = Cookie.get(self, 'currUsr')
        print usrCookie
        #Cookie.clear(self, 'currUsr')
        print "after clear"
        usrCookie = Cookie.get(self, 'currUsr')
        print usrCookie
        return


class PermaPost(Handler):

    def get(self):
        return


class Logout(Handler):

    def get(self):
        return


app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/', front),
    ('/blog/(\d+)', PermaPost),
    ('/logout', Logout),
], debug=True)
