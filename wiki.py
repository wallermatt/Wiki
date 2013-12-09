import webapp2
import cgi
import hmac
import logging
import random
from string import letters
import hashlib
import re

import os
from google.appengine.ext.webapp import template
from google.appengine.ext import db
from google.appengine.api import memcache

SECRET = 'XXXXXXXXXXXXX' # insert own secret phrase here
KEY    = 'top'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def set_secure_cookie(s):
    return s + '|' + hash_str(s)

def check_secure_cookie(s):
    name = str(s).split('|')[0]
    check_val = set_secure_cookie(name)
    if check_val == s:
        return True
    else:
        return False

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

def get_all_page_data():
    result = memcache.get(KEY)
    if result == None:
        result = db.GqlQuery("SELECT * FROM Page ORDER BY created DESC")
        memcache.set(KEY, result)
    return result
        
def select_page(all_pages, post_id):
    result = None
    highest_created_time = 0
    for entry in all_pages:
        if entry.page == post_id:
            if highest_created_time == 0:
                result = entry
                highest_created_time = entry.created
            if entry.created > highest_created_time:
                result = entry
                highest_created_time = entry.created
    return result

def select_view(all_pages, id_code):
    for entry in all_pages:
        if entry.key().id() == id_code:
            return entry
    return None

def get_latest_page(post_id, all_pages):
    single_page = None
    for entry in all_pages:
        if entry.page == post_id:
            if single_page == None:
                single_page = entry
            elif entry.created > single_page.created:
                single_page = entry
    return single_page

def generate_index_table(page_list):
    index_table = []
    for page in page_list:
        row = IndexRow(page)
        index_table.append(row)
    return index_table

def generate_history_table(page_list):
    history_table = []
    for page in page_list:
        row = HistoryRow(page.page, page.created, page.content[:50], str(page.key().id()))
        history_table.append(row)
    return history_table
    
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class WikiHandler(webapp2.RequestHandler):
        def display_template(self, html, template_values = {}):
                path = os.path.join(os.path.dirname(__file__), html)
                self.response.out.write(template.render(path,template_values))

        def check_logged_in(self):
                name = self.request.cookies.get('name')
                if check_secure_cookie(name):
                    return True
                else:
                    return False

class MainPage(WikiHandler):
        def get(self):
                logged_in = self.check_logged_in()
                logging.info('Logged in=' + str(logged_in))
                template_values = {'logged_in': logged_in}
                self.display_template('mainpage.html', template_values)

class Signup(WikiHandler):
        def get(self):
                template_values = {'logged_in': self.check_logged_in(),
                                   'history_page': None,
                                   'signup': True}
                self.display_template('base.html', template_values)
#                self.display_template('signup.html')
                
        def post(self):
                have_error = False
                name = self.request.get('username')
                password1 = self.request.get('password')
                password2 = self.request.get('verify')
                email = self.request.get('email')

                if not valid_username(name):
                    name_err = 'Invalid username'
                    have_error = True
                else:
                    q = db.GqlQuery("SELECT * FROM User WHERE name = '"+name+"'")
                    result = q.get()  
                    if result != None:
                        name_err = 'Username already exists'
                        have_error = True
                    else:
                        name_err = ''

                if not valid_password(password1):
                    password_err = 'Invalid password'
                    verify_err = ''
                    have_error = True
                elif password1 != password2:
                    verify_err = 'Passwords do not match!'
                    password_err = ''
                    have_error = True
                else:
                    password_err = ''
                    verify_err = ''
                    
                if not valid_email(email):
                    email_err = 'Invalid email'
                    have_error = True
                else:
                    email_err = ''

                if not have_error:
                    a = User(name=name,hash_pw = make_pw_hash(name, password1),email=email)
                    a.put()
                    name = str(set_secure_cookie(name))
                    self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % name)
                    self.redirect('/')
                    
                template_values = {'name': name,
                                   'email': email,
                                   'name_err': name_err,
                                   'password_err': password_err,
                                   'verify_err': verify_err,
                                   'email_err': email_err,
                                   'logged_in': self.check_logged_in(),
                                   'signup': True,
                                   'history_page': None}
                self.display_template('base.html', template_values)
#                self.display_template('signup.html', template_values)

class Login(WikiHandler):
        def get(self):
                template_values = {'logged_in': self.check_logged_in(),
                                   'history_page': None,
                                   'login': True}
                self.display_template('base.html', template_values)
#                self.display_template('login.html')
    
        def post(self):
                have_error = False
                name = self.request.get('username')
                password = self.request.get('password')
                q = db.GqlQuery("SELECT * FROM User WHERE name = '"+name+"'")
                result = q.get()  
                if result == None:
                    login_err = 'Invalid login'
                    have_error = True
                else:
                    if valid_pw(result.name, password, result.hash_pw) != True:
                        login_err = 'Invalid login'
                        have_error = True
                    else:
                        login_err = ''

                if not have_error:
                    name = str(set_secure_cookie(name))
                    self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/' % name)
                    self.redirect('/')

                template_values = {'logged_in': self.check_logged_in(),
                                   'history_page': None,
                                   'login_err':login_err,
                                   'login': True}
                self.display_template('base.html', template_values)
#                self.display_template('login.html', template_values)

class Logout(WikiHandler):
        def get(self):
                self.response.headers.add_header('Set-Cookie', 'name=;Path=/')
                self.redirect('/')


class EditPage(WikiHandler):
        def get(self, post_id):
                if not self.check_logged_in():
                    self.redirect('/')
                v = self.request.get("v")
                result = get_all_page_data()
                if result != None:
                    if v == '':
                        record = select_page(result, post_id)
                    else:
                        logging.info("v:", int(v))
                        record = select_view(result,int(v))
                    if record != None:
                        content = record.content
                    else:
                        content = ''
                else:
                    content = ''
                template_values = {
                                     'content': content,
                                     'history_page': '/_history' + post_id,
                                     'logged_in': self.check_logged_in(),
                                     'edit_page': post_id,
                                     'edit': True}
                self.display_template('base.html', template_values)   
#                self.display_template('_edit.html', template_values)
              
                    
                     
        def post(self, post_id):
                newpage = post_id
                content = self.request.get('content')
                a = Page(page = post_id, content = content)
                a.put()
                cache = memcache.get(KEY)
                if cache == None:
                    cache = []
                result = [a]
                for entry in cache:
                    if entry.created != a.created or entry.page != a.page:
                        result = result + [entry]
                logging.info(result)
                memcache.set(KEY, result)
                self.redirect(post_id)
                                      
class WikiPage(WikiHandler):
        def get(self, post_id):
                all_pages = get_all_page_data()
#                q = db.GqlQuery("SELECT * FROM Page WHERE  page = '"+post_id+"' ORDER BY created DESC LIMIT 1")
#                result = q.get()
                if all_pages == None:
                    single_page = None
                else:
                    single_page = get_latest_page(post_id, all_pages)
                if single_page == None:
                    self.redirect('/_edit' + post_id)
                else:
                    template_values = {'logged_in': self.check_logged_in(),
                                       'edit_page': '/_edit' + post_id,
                                       'history_page': '/_history' + post_id,
                                       'wikipage' : True,
                                       'page': single_page.page,
                                       'content': single_page.content}
                    self.display_template('base.html', template_values)
                    
                    

class HistoryPage(WikiHandler):
        def get(self, post_id):
                v = self.request.get("v")
                if v == '':
                    entries = []
                    all_pages = get_all_page_data()
                    for e in all_pages:
                        if e.page == post_id:
                            entries.append(e)
                    # fill historyrows
                    history_table = generate_history_table(entries)
                    template_values = {'logged_in': self.check_logged_in(),
#                                           'edit_page': '/_edit' + post_id,
                                           'history_page': '/_history' + post_id,
                                           'history': True,
                                           'history_table': history_table}
                    self.display_template('base.html', template_values)
                    
                else:
                     key = db.Key.from_path('Page', int(v))
                     page = db.get(key)
                     template_values = {'logged_in': self.check_logged_in(),
                                       'edit_page': '/_edit' + post_id + '?v=' + str(v),
                                       'history_page': '/_history' + post_id,
                                       'wikipage': True,
                                       'history': True,
                                       'page': page.page,
                                       'created': page.created,
                                       'content': page.content}
                     self.display_template('base.html', template_values)
                     
                            
class Flush(WikiHandler):
        def get(self):
            result = db.GqlQuery("SELECT * FROM Page ORDER BY created DESC")
            memcache.set(KEY, result)
            self.response.out.write('Flush')

class Cache(WikiHandler):
        def get(self):
            result = memcache.get(KEY)
            for entry in result:
                self.response.out.write('<br>')
                self.response.out.write(entry.page)
                self.response.out.write(entry.created)
                self.response.out.write(entry.content[:120])

class Frontpage(WikiHandler):
        def get(self):
            page_list = []
            all_pages = get_all_page_data()
            
            for e in all_pages:
                if e.page not in page_list:
                    page_list.append(e.page)
            index_table = []
            index_table = generate_index_table(page_list)
            template_values = {'logged_in': self.check_logged_in(),
                               'history_page': None,
                               'index': True,
                               'index_table':index_table}
            self.display_template('base.html', template_values)
           
            
class User(db.Model):
        name    = db.StringProperty(required = True)
        hash_pw = db.StringProperty(required = True)
        email   = db.StringProperty()

class Page(db.Model):
        page = db.StringProperty(required = True)
        content = db.TextProperty(required = True)
        created = db.DateTimeProperty(auto_now_add = True)

class IndexRow(object):
        def __init__(self, page):
            self.page = page
            self.view = page
            self.history = '/_history' + page
            self.edit    = '/_edit' + page

class HistoryRow(object):
        def __init__(self, page, created, content, page_id):
            self.page = page
            self.created = created
            self.content = content
            self.view = '/_history' + page + '?v=' + page_id 
            self.edit    = '/_edit' + page + '?v=' + page_id


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
                               ('/', Frontpage),
                               ('/signup', Signup),
                               ('/login', Login), 
                               ('/logout', Logout),
                               ('/flush', Flush),
                               ('/cache', Cache),
                               ('/_edit'+ PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)
