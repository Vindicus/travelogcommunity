from google.appengine.ext import db

from encrypt import HashInput


class User(db.Model):
    '''This is the User Model that stores new registered users'''
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    # This retrieves all entities with 'name'
    @classmethod
    def retrieve_user_info(cls, name):
        user_info = User.all().filter('name =', name).get()
        return user_info

    # logs user in and check if username exists
    # checks if password matches in datastore
    @classmethod
    def login(cls, name, password):
        # checks if username exists
        name_checked = cls.retrieve_user_info(name)
        # validates if password matches
        if name_checked:
            if HashInput.validate_password(password, name,
                                           name_checked.password):
                return True
            else:
                return False
        else:
            return False

    #  retrieves user id based on its username
    @classmethod
    def get_id(cls, name):
        u = User.all().filter('name =', name).get()
        return u.key().id()
