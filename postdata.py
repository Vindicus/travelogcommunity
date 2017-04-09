from google.appengine.ext import db


class PostData(db.Model):
    '''This Post Model that stores user posts'''
    subject = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateProperty(auto_now_add=True)
    creator = db.StringProperty(required=True)
    creator_name = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)
    dislikes = db.IntegerProperty(required=True)

    # performs a select query via GqlQuery
    @classmethod
    def select(cls, *ws):
        display_data = db.GqlQuery(*ws)
        return display_data

    # deletes a post by passing the post id
    @classmethod
    def deleted(cls, post_id):
        delete_post = post_id
        if delete_post:
            delete_post.delete()
            return True
        else:
            return False
