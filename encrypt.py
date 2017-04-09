import hmac

import random

import string


class HashInput():
    '''This creates a hash for username and password'''

    SECRET = 'F6#sd1Df-32s68901GvDjD3iskd3232AuU1'

    #  creates a salt
    @classmethod
    def salt_code(cls):
        return "".join(random.choice(string.letters) for x in xrange(5))

    #  hash username
    @classmethod
    def make_username_hash(cls, userid):
        u_hash = hmac.new(cls.SECRET, userid).hexdigest()
        return "%s|%s" % (userid, u_hash)

    #  extract username from the hash
    @classmethod
    def splice_username(cls, verify_username):
        user_id = verify_username.split('|')[0]
        if verify_username == HashInput.make_username_hash(user_id):
            return user_id

    #  hash the password
    @classmethod
    def make_pw_hash(cls, pwd, username, salt=""):
        if not salt:
            salt = cls.salt_code()
        pwd_hash = hmac.new(cls.SECRET, pwd+username+salt).hexdigest()
        return "%s,%s" % (salt, pwd_hash)

    #  validates if password matches password in user datastore
    @classmethod
    def validate_password(cls, input_password, username, db_password):
        salt_db_password = db_password.split(",")[0]
        return db_password == HashInput.make_pw_hash(input_password,
                                                     username,
                                                     salt_db_password)
