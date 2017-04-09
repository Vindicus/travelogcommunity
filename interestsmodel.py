from google.appengine.ext import db


class Interests(db.Model):
    '''This Interests Model keeps track of posts a user likes or dislikes'''
    post_id = db.StringProperty(required=True)
    interest = db.StringProperty(required=True)
    user_id = db.StringProperty(required=True)

    # performs a select query via GqlQuery
    @classmethod
    def select(cls, *ws, **kw):
        display_data = db.GqlQuery(*ws, **kw)
        return display_data
