#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import hashlib
import hmac
import string
import random
import re
import json
import urllib2
import logging

from datetime import datetime
from xml.dom import minidom
from google.appengine.api import memcache
from google.appengine.ext import db
from webapp2_extras import routes

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

SECRET = "imsosecret"								

##################
#GLOBAL FUNCTIONS#		
						
def hash_str(s):
	return hmac.new(SECRET, str(s)).hexdigest()
	
def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_secure_val(s):
	return "%s|%s" % (s, hmac.new(SECRET, str(s)).hexdigest())
		
def salted_hash(s, salt=None):
	if salt == None:
		salt = ''.join(random.choice(string.letters) for _ in range(5))
	return "%s|%s" % (salt, hash_str(s + salt))

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def verify_username(username):
	if not (username and USER_RE.match(username)):
		return "That is not a vaild username"
	elif User.gql("WHERE user_id = :1", username).get():
		return "That username is already taken"	

PASS_RE = re.compile(r"^.{3,20}$")
def verify_password(password):
	return not (password and PASS_RE.match(password))

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def verify_email(email):
	return not((not email) or EMAIL_RE.match(email))		
		
def verify_login(username, password):
	user = User.gql("WHERE user_id = :1", username).get()
	if user:
		if user.user_id == username and user.pass_id == salted_hash(password, user.pass_id.split("|")[0]):
			return user

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

def wiki_key(name = 'default'):
	return db.Key.from_path('wiki', name)

def memcache_get(memcache_key, update = False):
	client = memcache.Client()
	memcache_key = str(memcache_key)
	if client.gets(memcache_key) is None:
		if memcache_key == '_top':
			mem_obj = list(db.GqlQuery("SELECT * FROM Page ORDER BY created DESC"))
		else:
			mem_obj = list(db.GqlQuery("SELECT * FROM Page WHERE url_id = :1 ORDER BY created DESC", memcache_key))
		memcache.set(memcache_key, (mem_obj, datetime.utcnow()))
	(mem_obj, set_time) = memcache.get(memcache_key)
	if update:
		while True:
			(mem_obj, set_time) = client.gets(memcache_key)
			mem_obj = [update] + mem_obj
			if client.cas(memcache_key, (mem_obj, set_time)):
				break
	age = (datetime.utcnow() - set_time).total_seconds()
	return mem_obj, age


class User(db.Model):
	user_id = db.StringProperty(required = True)
	pass_id = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	email = db.StringProperty()

class Page(db.Model):
	url_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	edit_user = db.StringProperty(required = True)
	
	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("wiki_page.html", p = self)
		
	def render_json(self):
		obj = dict({'subject' : self.subject,
					'content' : self.content,
					'created' : self.created.strftime('%c'),
					'last_modified' : self.last_modified.strftime('%c'),
					})
		return obj
	
class MainHandler(webapp2.RequestHandler):
	def write(self, *args, **kwargs):
		self.response.out.write(*args, **kwargs)
		
	def render_str(self, template, **kwargs):
		t = jinja_env.get_template(template)
		return t.render(kwargs)
		
	def render(self, template, **kwargs):
		kwargs.update(self.log_kwargs)
		self.write(self.render_str(template, **kwargs))
	
	def get_cookie(self, value):
		return self.request.cookies.get(value)
		
	def check_secure_login(self):
		user_id = self.get_cookie("user_id")
		if user_id:
			if check_secure_val(user_id):
				return user_id.split("|")[0]
			else:
				self.logout()
				
	def login(self, username, password):
		user = User.gql("WHERE user_id = :1", username).get()
		if user:
			if user.user_id == username and user.pass_id == salted_hash(password, user.pass_id.split("|")[0]):
				#self.response.headers.add_header("Set-Cookie", "user_id=%s;Path=/" % str(make_secure_val(user.key().id())))
				self.response.set_cookie('user_id', str(make_secure_val(user.key().id())), max_age=360, path='/')
				self.redirect("/wiki")
			else:
				return "Invalid username password combination"
		else:
			return "Username is not registered"
	
	def logout(self):
		self.response.delete_cookie('user_id')
		
	def write_json(self, pages):
		self.response.headers["Content-Type"] = 'application/json'
		obj = [page.render_json() for page in pages]
		self.write(json.dumps(obj))
		
	def initialize(self, *args, **kwargs):
		webapp2.RequestHandler.initialize(self, *args, **kwargs)
		user = self.check_secure_login()
		
		if user:
			key = db.Key.from_path("User", int(user), parent=wiki_key())
			user = db.get(key)
			self.log_kwargs = dict(login = "logout",
								   login_url = "/wiki/logout",
								   signup = user.user_id,
								   #signup_url = "",
								   #history = "history"
								   #history_url = "/wiki/" + url "/history"
								   )
		else:
			self.log_kwargs = dict(login = "login",
								   login_url = "/wiki/login",
								   signup = "signup",
								   signup_url = "/wiki/signup"
								   )
		
class SignupPage(MainHandler):
	def get(self):
		self.render("signup.html")
		
	def post(self):
		error_list = ["e_username", "e_password", "e_verify", "e_email"]
		username = self.request.get("username")
		password = self.request.get("password")
		verify = self.request.get("verify")
		email = self.request.get("email")
		
		kwargs = dict(username=username, email=email)
		e_username = verify_username(username)
		if e_username:
			kwargs['e_username'] = e_username
		if verify_password(password):
			kwargs['e_password'] = "That was not a valid password"
		elif password != verify:
			kwargs['e_verify'] = "Passwords do not match"
		if verify_email(email):
			kwargs['e_email'] = "That was not a vaild email"
			
		if any(key in error_list for key in kwargs.keys()):
			self.render("signup.html", **kwargs)
		else:
			u = User(parent=wiki_key(), user_id = username, pass_id = salted_hash(password), email_id = email)
			u.put()
			user = db.get(u.key())
			self.login(username, password)
			
class LoginPage(MainHandler):
	def get(self):
		self.render("login.html")
		
	def post(self):
		page = self.request.get("page")	
		username = self.request.get("username")
		password = self.request.get("password")
		
		kwargs = dict(username=username)
		kwargs['e_username'] = self.login(username=username, password=password)
		if kwargs['e_username']:
			self.render("login.html", **kwargs)
			
class LogoutPage(MainHandler):
	def get(self):
		self.logout()
		self.redirect("/wiki")
	
class EditPage(MainHandler):
	#display latest edit of page
	def get(self, url, json):
		pages, age = memcache_get(url)
		if not pages:
			self.render("edit_page.html")
		else:
			page = pages[0]
			kwargs = dict(content = page.content, edit_user = page.edit_user, age = age)
			self.render("edit_page.html", **kwargs)
		
	def post(self, url, **kwargs):	
		content = self.request.get('content')
		edit_user = "test_user"
		p = Page(parent=wiki_key(), url_id = url, content = content, edit_user = edit_user)
		p.put()
		memcache_get(url, p)
		memcache_get('_top', p)
		self.redirect('/wiki/' + url)
		
class WikiPage(MainHandler):
	def get(self, url, json):
		#redirect to edit handler if page does not exist else display latest edit
		pages, age = memcache_get(url)
		if not pages:
			self.redirect('/wiki/_edit/' + url)
		else:
			kwargs = dict(page = pages[0])
			self.render("permalink.html", **kwargs)
			
class WikiFront(MainHandler):
	def get(self):
		#some way to list all current pages
		pages, age = memcache_get('_top')
		logging.error(pages)
		self.render("wiki_front.html", pages=pages, age=age)
		
# class History(MainHandler):
	# def get(self, url):
		# pages, age = memcache_get(url)
		# self.render("history.html", **kwargs)
		
class FlushPage(MainHandler):
	def get(self):
		memcache.flush_all()
		self.redirect('/blog')
		
app = webapp2.WSGIApplication([
webapp2.SimpleRoute(r'/wiki/?', handler=WikiFront, name='wikifront'),
routes.PathPrefixRoute(r'/wiki', [
	webapp2.Route(r'/login', handler=LoginPage, name='login'),
	webapp2.Route(r'/signup', handler=SignupPage, name='signup'),
	webapp2.Route(r'/logout', handler=LogoutPage, name='logout'),
	webapp2.Route(r'/flush', handler=FlushPage, name='flushmemcache'),
	webapp2.Route(r'/_edit/<url:\w+><json:(\.json$)?>', handler=EditPage, name='editpage'),
	webapp2.Route(r'/<url:\w+><json:(\.json$)?>', handler=WikiPage, name='wikipage'),
	])], debug=True)
