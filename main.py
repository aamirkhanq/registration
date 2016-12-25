import webapp2
import os
import jinja2
import re
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                              autoescape = True)

SECRET="iamjustsosecret"

def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s"%(s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
       
class MainPage(Handler):
    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return PASS_RE.match(password)

    def valid_email(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)

    def write_form(self, template, username = "", username_error = "",
                   password_error = "", password_unmatch_error = "",
                   email_error = ""):
        users = db.GqlQuery("SELECT * from User")
        self.render(template, entered_value = username, username_error = username_error,
                    password_error = password_error,
                    password_unmatch_error = password_unmatch_error,
                    email_error = email_error, users = users)

    def set_cookie(self, user_id):
        self.response.headers['Content Type'] = 'text/plain'
        self.response.headers.add_header('Set-Cookie', 'user_id=%s;Path=/'%make_secure_val(str(user_id)))
        self.redirect("/thanks")
        

    def create_user(self, username, password):
        allow_username = True
        users = User.all()
        for user in users:
            if username == user.username:
                allow_username = False
                        
        if allow_username:
            new_user = User(username = username, password = password)
            new_user.put()
            self.set_cookie(new_user.key().id())
            #self.redirect('/thanks?username=%s'%username)
        else:
            username_error = "User already exists"
            self.write_form("signup.html", username, username_error)
    
    def get(self):
        self.write_form("signup.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        valid_username = self.valid_username(username)
        
        valid_password = self.valid_password(password)
                    
        valid_email = self.valid_email(email)

        username_error = password_error = password_unmatch_error = email_error = ""

        if valid_username == None:
            username_error = "That's not a valid username"

        if valid_password == None:
            password_error = "That's not a valid password"

        if password != verify:
            password_unmatch_error = "Both the passwords should match"
        
        if email:
            if valid_email == None:
                    email_error = "That's not a valid email"

        if email:
            if valid_username != None and valid_password != None and valid_email != None and password == verify and username_error == "":
                self.create_user(username, password)
                #self.redirect("/thanks?username=%s"%username)
            else:
                self.write_form("signup.html", username, username_error, password_error,
                                password_unmatch_error, email_error)
        else:
            if valid_username != None and valid_password != None and password == verify and username_error == "":
                self.create_user(username, password)
                #self.redirect("/thanks?username=%s"%username)
            else:
                self.write_form("signup.html", username, username_error, password_error,
                                password_unmatch_error)

class ThanksHandler(Handler):
    def get(self):
        user = self.request.cookies.get('user_id')
        cookie_val = check_secure_val(user)
        if cookie_val:
            usr = User.get_by_id(int(cookie_val))
            self.render("thanks.html",username = usr.username)
        else:
            self.redirect("/signup")
        
app = webapp2.WSGIApplication([
    ('/signup', MainPage),('/thanks', ThanksHandler)
], debug=True)
