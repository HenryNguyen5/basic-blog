# os funcs and regex
import os
import re

# minimal web frameworks
import webapp2
import jinja2
import json

# hashing libs for cookies && passowrds
import hmac
import hashlib
import random
from string import letters

# google datastore
from google.appengine.ext import db
from datetime import datetime

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def getCurTime():
    fmttedTime = '{t.year}/{t.month}/{t.day} | {t.hour}:{t.minute:02}'.format(
        t=datetime.now())
    return fmttedTime


class Valid():
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    @classmethod
    def username(cls, username):
        # check if username exists
        if User.getByName(username):
            return False
        return cls.USER_RE.match(username)

    @classmethod
    def password(cls, password):
        return cls.PASS_RE.match(password)

    @classmethod
    def email(cls, email):
        return (cls.EMAIL_RE.match(email) or email == '')

    @classmethod
    def verifyCmp(cls, password, verify):
        return password == verify

    @classmethod
    def register(cls, regDict):
        errDict = {}
        if not cls.username(regDict["username"]):
            errDict["errUsername"] = "Not a valid username"
        if not cls.password(regDict["password"]):
            errDict["errPassword"] = "Not a valid password"
        if not cls.verifyCmp(regDict["password"], regDict["verify"]):
            errDict["errVerify"] = "Your passwords do not match"
        if not cls.email(regDict["email"]):
            errDict["errEmail"] = "Not a valid email"

        return errDict


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
        val = str(val)
        h = cls.__gen(hmac.new, cls.cookieSecret, val)
        return '{value}|{hash}'.format(value=val, hash=h)

    @classmethod
    def password(cls, username, pwd, salt=''):
        if not salt:
            salt = cls.__genSalt()

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

        # invalid cookies get cleared
        else:
            Cookie.clear(caller, name)

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
    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    lastModified = db.DateTimeProperty(auto_now=True)
    # array of names that liked this post
    likes = db.ListProperty(item_type=str, default=[])
    # will be array of Posts
    comments = db.TextProperty(default='{}')

    @classmethod
    def new(cls, author, subject, content):
        p = Post(author=author, subject=subject, content=content)
        p.put()
        return p

    @classmethod
    def getByName(cls, name):

        # get the user object
        queryString = "WHERE subject = '{name}'".format(name=name)

        # get first entry
        return cls.gql(queryString).get()

    @classmethod
    def getById(cls, postID):
        return cls.get_by_id(int(postID))

    @classmethod
    def getRecent(cls, amtToReturn=10):
        queryString = "ORDER BY created DESC LIMIT {limit}".format(
            limit=amtToReturn)
        return cls.gql(queryString)

    @classmethod
    def getComment(cls, postID, commentID):
        p = cls.getById(postID)
        loadedComments = json.loads(p.comments)
        return loadedComments[commentID]

    def like(self, currUsr):
        likeVal = len(self.likes)
        # make sure they havent liked already && isnt author
        if(currUsr.name not in self.likes) and (currUsr.name != self.author):
            self.likes.append(currUsr.name)
            likeVal += 1

        # if they alraedy liked and arent author, unlike
        elif (currUsr.name in self.likes) and (currUsr.name != self.author):
            self.likes.remove(currUsr.name)
            likeVal -= 1

        self.put()
        return likeVal

    def edit(self, subject, content):
        if not subject and not content:
            return False
        self.subject = subject
        self.content = content
        self.put()
        return True

    def addComment(self, currUsr, comment):
        loadedComments = json.loads(self.comments)
        numOfComments = str(len(loadedComments) + 1)
        loadedComments[numOfComments] = {
            'author': currUsr.name,
            'content': comment,
            'created': getCurTime(),
            'edited': getCurTime()
        }
        self.comments = json.dumps(loadedComments)
        self.put()

    def editComment(self, currUsr, comment, commentID):
        # get dict of comments for this post
        loadedComments = json.loads(self.comments)

        c = loadedComments.get(commentID)
        if not c or not comment:
            return False

        # validate its the right user
        if c["author"] != currUsr.name:
            return False
        else:
            c["content"] = comment
            c["edited"] = getCurTime()
            # set to json string and store
            self.comments = json.dumps(loadedComments)
            self.put()
            return True

    def deleteComment(self, currUsr, commentID):
        # get dict of comments for this post
        loadedComments = json.loads(self.comments)

        # validate user
        c = loadedComments.get(commentID)
        if not c:
            return False

        # validate its the right user
        if c["author"] != currUsr.name:
            return False
        else:
            del loadedComments[commentID]
            self.comments = json.dumps(loadedComments)
            self.put()
            return True

    def listComments(self):

        loadedComments = json.loads(self.comments)
        l = loadedComments.items()
        l.sort(key=lambda val: int(val[0]))
        return l


class User(db.Model):

    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    lastLoginTime = db.StringProperty(required=True, default=getCurTime())

    @classmethod
    def Login(cls, name, password):
        curUsr = cls.getByName(name)
        # check if username exists
        if not curUsr:
            return False
        # split the salt and hashed pw from the user obj
        hashedPwArr = curUsr.password.split('|')
        hashPw = hashedPwArr[0]
        salt = hashedPwArr[1]
        inputtedPass = Hash.password(name, password, salt).split('|')[0]
        # check if hashedPw matches with users inputted pw
        if hashPw == inputtedPass:
            return curUsr
        else:
            return False

    @classmethod
    def Logout(cls, uid):
        if not uid:
            return
        curUsr = cls.getById(uid)
        if not curUsr:
            return
        # set last login time before logging out
        curUsr.lastLoginTime = getCurTime()
        curUsr.put()
        return

    @classmethod
    def getByName(cls, name):

        # get the user object
        queryString = "WHERE name = '{name}'".format(name=name)

        # get first entry
        return cls.gql(queryString).get()

    @classmethod
    def getById(cls, uid):
        if not uid.isdigit():
            return
        return cls.get_by_id(int(uid))

    @classmethod
    def register(cls, name, password, email=''):
        password = Hash.password(name, password)
        user = User(name=name, password=password,
                    email=email, username=name)
        user.put()
        return user


class Signup(Handler):

    def renderSignup(self, username='', email='', **kwargs):
        curUsr = {'name': 'anon', 'lastLoginTime': 'Now'}
        return self.render('signup.html', username=username, email=email, user=curUsr, **kwargs)

    def get(self):
        return self.renderSignup()

    def post(self):
        regDict = {}
        errDict = {}
        regDict["username"] = self.request.get('username')
        regDict["password"] = self.request.get('password')
        regDict["verify"] = self.request.get('verify')
        regDict["email"] = self.request.get('email')
        errDict = Valid.register(regDict)
        if errDict:
            return self.renderSignup(regDict["username"], regDict["email"], **errDict)
        registeredUsr = User.register(regDict["username"], regDict[
            "password"], regDict["email"])

        # set cookie to current userID
        Cookie.set(self, 'uid', registeredUsr.key().id())

        # redirect to front page after
        return self.redirect('/')



class Front(Handler):

    def get(self):
        c = Cookie.get(self, 'uid')
        curUsr = {'name': 'anon', 'lastLoginTime': 'Now'}
        if c:
            curUsr = User.getById(c)

        recentPosts = Post.getRecent()
        self.render('main.html', blogs=recentPosts, user=curUsr)


class PermaPost(Handler):

    def get(self, postID):
        uid = Cookie.get(self, 'uid')

        # get curr user
        currUsr = User.getById(uid)
        if not currUsr:
            currUsr = {'name': 'anon', 'lastLoginTime': 'Now'}

        p = Post.getById(postID)
        if not p:
            return self.redirect('/')

        return self.render('post.html', post=p, user=currUsr)


class Logout(Handler):

    def get(self):
        uid = Cookie.get(self, 'uid')

        User.Logout(uid)
        Cookie.clear(self, 'uid')
        return self.redirect('/')


class Welcome(Handler):

    def get(self):
        c = Cookie.get(self, 'uid')
        if not c:
            return self.redirect('/signup')
        curUsr = User.getById(c)
        self.render('welcome.html', user=curUsr)


class Login(Handler):

    def renderLogin(self, username='', error=''):
        curUsr = {'name': 'anon', 'lastLoginTime': 'Now'}
        return self.render('login.html', username=username, error=error, user=curUsr)

    def get(self):
        return self.renderLogin()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        curUsr = User.Login(username, password)

        if not curUsr:
            err = "Invalid username/password"
            return self.renderLogin(username, error=err)

        # set cookie to current userID
        Cookie.set(self, 'uid', curUsr.key().id())

        # redirect to front page after
        return self.redirect('/')



class GenericPost(Handler):

    def getPostAndUsr(self, postID, sameUsrAsPost=True):
        uid = Cookie.get(self, 'uid')
        if not uid:
            return
        # get curr user
        currUsr = User.getById(uid)

        # check if currUsr is blog post author
        p = Post.getById(postID)
        if (not currUsr.name == p.author) and (sameUsrAsPost):
            return
        return [p, currUsr]


class NewPost(Handler):

    def renderNewPost(self, subject="", content="", error="", currUsr={'name': 'anon', 'lastLoginTime': 'Now'}):
        self.render("newpost.html", subject=subject,
                    content=content, error=error, user=currUsr)

    def get(self):
        uid = Cookie.get(self, 'uid')
        if not uid:
            return self.redirect('/login')
        currUsr = User.getById(uid)
        self.renderNewPost(currUsr=currUsr)

    def post(self):
        uid = Cookie.get(self, 'uid')
        if not uid:
            self.redirect('/login')

        # get curr user
        currUsr = User.getById(uid)
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post.new(author=currUsr.name,
                         subject=subject, content=content)
            postID = p.key().id()
            # store to db
            currUsr.put()
            # get rid of redirect msg
            return self.redirect("/blog/" + str(postID))

        else:
            error = "We need both a subject and some content!"
            self.renderNewPost(content=content,
                               subject=subject, error=error, currUsr=currUsr)


class EditPost(GenericPost):

    def renderEditPost(self, subject="", content="", error="", currUsr={'name': 'anon', 'lastLoginTime': 'Now'}, pID=''):
        self.render("editpost.html", subject=subject,
                    content=content, error=error, user=currUsr, pID=pID)

    def get(self, postID):
        try:
            p, currUsr = self.getPostAndUsr(postID)
        except TypeError:
            return self.redirect('/')
        self.renderEditPost(subject=p.subject,
                            content=p.content, pID=postID)

    def post(self, postID):

        try:
            p, currUsr = self.getPostAndUsr(postID)
        except TypeError:
            return self.redirect('/')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if not p.edit(subject, content):
            error = "We need both a subject and some content!"
            return self.renderEditPost(content=content,
                                       subject=subject, error=error, currUsr=currUsr, pID=postID)

        return self.redirect("/blog/" + str(postID))


class DeletePost(GenericPost):

    def get(self, postID):
        try:
            p, currUsr = self.getPostAndUsr(postID)
        except TypeError:
            return self.redirect('/')
        p.delete()
        return self.redirect('/')


class LikePost(GenericPost):

    def get(self, postID):
        try:
            p, currUsr = self.getPostAndUsr(postID, sameUsrAsPost=False)
        except TypeError:
            return self.redirect('/')

        resp = {"val": p.like(currUsr), "postID": postID}
        self.response.write(json.dumps(resp))


class AddComment(PermaPost):

    def renderAddComment(self, content="", error="", currUsr={'name': 'anon', 'lastLoginTime': 'Now'}, p=''):
        self.render("post.html",
                    commentContent=content, error=error, user=currUsr, post=p)

    def post(self, postID):
        uid = Cookie.get(self, 'uid')
        if not uid:
            return self.redirect('/login')

        # get curr user
        currUsr = User.getById(uid)
        p = Post.getById(postID)
        content = self.request.get('commentContent')

        if content:
            p.addComment(currUsr, content)

            # get rid of redirect msg
            return self.redirect("/blog/" + str(postID))

        else:
            error = "We need some content!"
            self.renderAddComment(content=content,
                                  error=error, currUsr=currUsr, p=p)


class EditComment(Handler):

    def renderEditComment(self, content="", error="", currUsr={'name': 'anon', 'lastLoginTime': 'Now'}, pID='', cID=''):
        self.render("editcomment.html",
                    content=content, error=error, user=currUsr, pID=pID, cID=cID)

    def get(self, postID, commentID):
        uid = Cookie.get(self, 'uid')
        if not uid:
            return self.redirect('/login')
        currUsr = User.getById(uid)
        c = Post.getComment(postID, commentID)

        self.renderEditComment(content=c['content'], currUsr=currUsr, pID=postID, cID=commentID)

    def post(self, postID, commentID):
        uid = Cookie.get(self, 'uid')
        if not uid:
            return self.redirect('/login')

        currUsr = User.getById(uid)
        p = Post.getById(postID)
        content = self.request.get('content')

        if not p.editComment(currUsr, content, commentID):
            error = "We need some content!"
            return self.renderEditComment(content=content, currUsr=currUsr, pID=postID, cID=commentID, error=error)

        return self.redirect("/blog/" + str(postID))


class DeleteComment(Handler):

    def get(self, postID, commentID):
        uid = Cookie.get(self, 'uid')
        if not uid:
            return self.redirect('/login')

        currUsr = User.getById(uid)
        p = Post.getById(postID)

        p.deleteComment(currUsr, commentID)

        return self.redirect("/blog/" + str(postID))


app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/', Front),
    ('/blog/(\d+)', PermaPost),
    ('/blog/(\d+)/edit', EditPost),
    ('/blog/(\d+)/delete', DeletePost),
    ('/blog/(\d+)/like', LikePost),
    ('/blog/(\d+)/addcomment', AddComment),
    ('/blog/(\d+)/editcomment/(\d+)', EditComment),
    ('/blog/(\d+)/deletecomment/(\d+)', DeleteComment),
    ('/login', Login),
    ('/welcome', Welcome),
    ('/logout', Logout),
    ('/newpost', NewPost)
], debug=True)
