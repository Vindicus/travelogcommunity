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
from encrypt import HashInput

from usermodel import User

from postdata import PostData

from comments import CommentPost

from interestsmodel import Interests

import re

import random

import time

import os

import webapp2

import jinja2


#  Creates jinja template
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

#  Constant variables for validating against regular expressions
USER_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_REGEX = re.compile(r"^.{3,20}$")
EMAIL_REGEX = re.compile(r"^[\S]+@[\S]+.[\S]+$")


#  validates username during signup
def username_validation(user):
    return USER_REGEX.match(user)


#  validates password during signup
def password_validation(password):
    return PASSWORD_REGEX.match(password)


#  validates email during signup
def email_validation(email):
    return EMAIL_REGEX.match(email)


#  base class handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # validates if user logged in during load
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_cookie = self.request.cookies.get("userid")
        self.creator = ""
        self.user = ""
        if user_cookie:
            userid = HashInput.splice_username(user_cookie)  # user id
            self.user = userid
            self.creator = User.get_by_id(int(self.user))  # username
        else:
            self.user = False
            self.creator = False


class HomeHandler(Handler):
    '''The handler to retrieve the homepage'''
    def get(self):
        self.render("homepage.html", registered_user=self.user)


#  The handler to retrieve all posts from datastore
class BlogHandler(Handler):
    def get(self):
        if self.user:
            #  queries all the posts in descending order and pass to index.html
            display_data = PostData.select("SELECT * FROM PostData ORDER BY \
            created DESC")
            self.render("index.html", display_data=display_data,
                        registered_user=self.user)
        else:
            self.redirect('/')


class UserSession(Handler):
    '''base class for user authentication/creation from base Handler'''
    #  successful login creates cookie
    def login(self, username):
        self.response.headers.add_header("Set-Cookie", "userid =%s" %
                                         (HashInput.make_username_hash
                                          (str(User.get_id(username)))), path='/')

    #  log user out setting cookie to empty
    def logout(self):
        self.response.headers.add_header("Set-Cookie", "userid=", path='/')

    #  Create user account
    def create_user_account(self, username, password, email):
        pwd_hash = HashInput.make_pw_hash(password, username)
        user_db = User(name=username, password=pwd_hash, email=email)
        user_db.put()
        userid = user_db.key().id()
        self.response.headers.add_header("Set-Cookie", "userid =%s" %
                                         (HashInput.make_username_hash
                                          (str(userid))), path='/')

    #  Check if the username already exists in the system
    def duplicated_username(self, username):
        duplicate_user = False
        if User.retrieve_user_info(username):
            duplicate_user = True
        return duplicate_user


class DeletePostHandler(Handler):
    '''Deletes the post'''
    def get(self, post_id):
        if self.user:
            #  retrieves entity by ID
            post = PostData.get_by_id(int(re.escape(post_id)))
            # only registered user can remove its own posts
            if post.creator == self.user:
                if PostData.deleted(post):
                    comment_data = PostData.select("SELECT * FROM \
                                                   CommentPost WHERE \
                                                   by_post = :1",
                                                   re.escape(post_id))
                    #  when a post is deleted:
                    #  go and delete the comments related to it
                    for c_data in comment_data:
                        c_data.delete()
                    time.sleep(0.5)
                    self.redirect("/blog")
                else:
                    self.write("Failed to delete")
            else:
                self.write("This is not your post, cannot delete")
        else:
            self.redirect("/blog/login")


class PostPageHandler(Handler):
    '''Display 1 post with edit, delete, comment, likes, dislikes '''
    def get(self, post_id):
        post = PostData.get_by_id(int(re.escape(post_id)))
        comment_data = PostData.select("SELECT * FROM \
                                       CommentPost WHERE \
                                       by_post = :1", re.escape(post_id))

        if self.user:
            if post:
                self.render("permalink.html", post=post, user=self.user,
                            comment_query=comment_data, commentdata="",
                            registered_user=self.user)
            else:
                self.error(404)
        else:
                self.redirect("/blog/login")

    def post(self, post_id):
        if self.user:
            action = self.request.get("action")
            update_id = self.request.get("update", default_value="")
            comment_post = self.request.get("comment-post")

            #  user submits and updates an existing comment
            if action == "comment" and not update_id == "":
                cmt = CommentPost.get_by_id(int(update_id))
                cmt.comment = comment_post
                cmt.put()
                time.sleep(0.5)
                self.redirect(self.request.url)

                # user submits a new comment
            elif action == "comment":
                comment_store = CommentPost(comment=comment_post,
                                            by_user_name=self.creator.name,
                                            by_post=re.escape(post_id),
                                            user_id=self.user)

                comment_store.put()
                time.sleep(0.5)
                self.redirect(self.request.url)

            # user likes a post and javascript submits a form
            if action == "like":
                post = PostData.get_by_id(int(re.escape(post_id)))
                if not self.user == post.creator:
                    get_interest = Interests.select("SELECT * FROM Interests where post_id=:1 AND user_id=:2", post_id, self.user).get()

                    if get_interest and get_interest.user_id == self.user:
                        if get_interest.interest == "dislike":
                            post.dislikes = post.dislikes - 1
                            post.likes = post.likes + 1
                            post.put()
                            get_interest.interest = "like"
                            get_interest.put()
                            self.redirect(self.request.url)
                        else:
                            self.redirect(self.request.url)
                    else:
                        interest = Interests(post_id=str(post.key().id()),
                                             interest="like",
                                             user_id=self.user)
                        interest.put()
                        post.likes = post.likes + 1
                        post.put()
                        self.redirect(self.request.url)

            # user dislikes a post and javascript submits a form
            if action == "dislike":
                post = PostData.get_by_id(int(re.escape(post_id)))
                if not self.user == post.creator:
                    get_interest = Interests.select("SELECT * FROM Interests where post_id=:1 AND user_id=:2", post_id, self.user).get()
                    if get_interest and get_interest.user_id == self.user:
                        if get_interest.interest == "like":
                            post.likes = post.likes - 1
                            post.dislikes = post.dislikes + 1
                            post.put()
                            get_interest.interest = "dislike"
                            get_interest.put()
                            self.redirect(self.request.url)
                        else:
                            self.redirect(self.request.url)

                    else:
                        interest = Interests(post_id=str(post.key().id()),
                                             interest="dislike",
                                             user_id=self.user)
                        interest.put()
                        post.dislikes = post.dislikes + 1
                        post.put()
                        self.redirect(self.request.url)

            # populates existing comment in the field with javascript
            if action == "edit":
                post = PostData.get_by_id(int(re.escape(post_id)))
                comment_data = PostData.select("SELECT * FROM \
                                               CommentPost WHERE \
                                               by_post = :1",
                                               re.escape(post_id))

                commentEdit = self.request.get("commentEdit")
                commentPost = CommentPost.get_by_id(int(commentEdit))
                self.render("permalink.html", post=post,
                            user=self.user, comment_query=comment_data,
                            commentdata=commentPost)

            # user deletes a comment
            if action == "delete":
                commentDelete = self.request.get("commentDelete")
                commentPost = CommentPost.get_by_id(int(commentDelete))
                commentPost.delete()
                time.sleep(0.5)
                self.redirect(self.request.url)
        else:
            self.error(404)


class EditPostHandler(Handler):
    '''Edit posts'''
    def get(self, post_id):
        post = PostData.get_by_id(int(re.escape(post_id)))
        if self.user:
            if post.creator == self.user:
                self.render("edit.html", post=post, registered_user=self.user)
            else:
                self.write("cannot edit post")
        else:
            self.redirect("/blog/login")

    def post(self, post_id):
        if self.user:
            action = self.request.get("action")
            if action == "cancel":
                self.redirect('/blog')
            else:
                edit_subject = self.request.get("subject")
                edit_post = self.request.get("post")
                postdata = PostData.get_by_id(int(re.escape(post_id)))
                postdata.subject = edit_subject
                postdata.post = edit_post
                postdata.put()
                self.redirect('/blog/%s' % (re.escape(post_id)))
        else:
            self.error(404)


class NewPostHandler(Handler):
    '''Handles new post creation '''
    def new_post(self, subject="", post="", error=""):
        self.render("/newpost.html", subject=subject,
                    post=post, error=error,
                    registered_user=self.user)

    def get(self):
        if self.user:
            self.new_post()
        else:
            self.redirect('/blog/login')

    def post(self):
        if self.user:
            subject = self.request.get("subject")
            post = self.request.get("post")

            #  Verifies if subject and post is not empty
            if subject and post:
                post_store = PostData(subject=subject,
                                      post=post, creator=self.user,
                                      likes=0, dislikes=0,
                                      creator_name=self.creator.name)

                post_store.put()
                time.sleep(0.5)
                self.redirect('/blog/%s' % str(post_store.key().id()))
            else:
                error = "Please fill in all fields"
                self.new_post(subject, post, error)
        else:
            self.error(404)


class LoginHandler(UserSession):
    '''user logins '''
    #  validates user input
    def form_validation(self, username, password):
        prompt_errors = dict()
        valid_error = False

        if username == "":
            prompt_errors["username_error"] = "username is blank"
            valid_error = True

        if password == "":
            prompt_errors["password_error"] = "password is blank"
            valid_error = True

        return valid_error and prompt_errors

    def get(self):
            if self.user:
                self.redirect("/blog")
            else:
                self.render("login.html")

    def post(self):
            username = self.request.get("username").upper()
            password = self.request.get("password")
            contain_errors = self.form_validation(username, password)
            if contain_errors:
                self.render("login.html", **contain_errors)
            else:
                user = User.login(username, password)
                #  Pass username and password to database
                #  verify its existence and pass in True
                if user:
                    #  If user exists in the system:
                    #  create cookie by logging user in
                    self.login(username)
                    self.redirect("/blog")
                else:
                    self.render("login.html",
                                authentication_error="Login/Password Mismatch")


class LogoutHandler(UserSession):
    '''user logs out'''
    def get(self):
        self.logout()
        self.redirect("/blog/login")


class SignUpHandler(UserSession):
    '''user signs up'''
    def form_validation(self, username, password, confirm, email):
        prompt_errors = dict()

        valid_error = False

        if username == "":
            prompt_errors["username_error"] = "username is blank"
            valid_error = True
        elif not username_validation(username):
            prompt_errors["username_error"] = "username does not \
                                               meet the requirements"
            valid_error = True

        if password == "":
            prompt_errors["password_error"] = "password is blank"
            valid_error = True
        elif not password_validation(password):
            prompt_errors["password_error"] = "password does not \
                                               meet the requirements"
            valid_error = True

        if confirm == "":
            prompt_errors["verify_error"] = "please confirm password"
            valid_error = True
        elif not password == confirm:
            prompt_errors["verify_error"] = "Password does not match"
            valid_error = True

        if email == "":
            prompt_errors["email_error"] = "email is blank"
            valid_error = True
        elif not email_validation(email):
            prompt_errors["email_error"] = "Please enter valid email"
            valid_error = True

        return valid_error and prompt_errors

    def get(self):
        if self.user:
            self.redirect("/blog")
        else:
            self.render("signup.html")

    def post(self):
        username = self.request.get("username").upper()
        password = self.request.get("password")
        confirm = self.request.get("confirm")
        email = self.request.get("email")
        contain_errors = self.form_validation(username,
                                              password, confirm, email)

        if contain_errors:
            self.render("signup.html", **contain_errors)
        elif self.duplicated_username(username):
            username_error = "Please choose a different username"
            self.render("signup.html", username_error=username_error)
        else:
            #  Create user account if all validation passes
            self.create_user_account(username, password, email)
            self.redirect("/blog")

#  url routes to handlers
app = webapp2.WSGIApplication([
        ('/blog', BlogHandler),
        ('/', HomeHandler),
        ('/blog/newpost', NewPostHandler),
        ('/blog/([0-9]+)', PostPageHandler),
        ('/blog/signup', SignUpHandler),
        ('/blog/login', LoginHandler),
        ('/blog/logout', LogoutHandler),
        ('/blog/delete/([0-9]+)', DeletePostHandler),
        ('/blog/edit/([0-9]+)', EditPostHandler)
], debug=True)
