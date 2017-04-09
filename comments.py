from google.appengine.ext import db


class CommentPost(db.Model):
    '''Stores multiple user comments'''
    comment = db.TextProperty(required=True)
    user_id = db.StringProperty(required=True)
    by_user_name = db.StringProperty(required=True)
    by_post = db.StringProperty(required=True)
    last_created = db.DateTimeProperty(auto_now=True)
