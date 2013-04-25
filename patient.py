#!/usr/bin/env python
# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:fdm=marker:ai
from flask import Flask, request, redirect, url_for, session, flash, g, \
     render_template
from flask_oauth import OAuth

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# configuration
DATABASE_URI = 'sqlite:////tmp/flask-oauth.db'
SECRET_KEY = 'development key'
DEBUG = True

# setup flask
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

# Use oyoh as example remote application
oyoh = oauth.remote_app('oyoh',
    # unless absolute urls are used to make requests, this will be added
    # before all URLs. This is also true for request_token_url and others.
    base_url='https://cajuncodefest.dhh.la.gov/api/v1/',
    # where flask should look for new request tokens
    request_token_url=None,
    # where flask should exchange the token with the remote application
    # access_token_url='https://cajuncodefest.dhh.la.gov/oauth/token',
    access_token_url='https://cajuncodefest.dhh.la.gov/oauth/token',
    access_token_method='POST',
    request_token_params={'response_type': 'code'},
    access_token_params={'grant_type': 'authorization_code'},
    # oyoh knows two authorizatiom URLs. /authorize and /authenticate.
    # they mostly work the same, but for sign on /authenticate is
    # expected because this will give the user a slightly different
    # user interface on the oyoh side.
    authorize_url='https://cajuncodefest.dhh.la.gov/oauth/authorize',
    # the consumer keys from the oyoh application registry.
    consumer_key='c7222ef96c60119bbf2b394a7c460a56a13c4e5b01ab9a394d63fb1c23106f65',
    consumer_secret='bc2180403617de236264a08039948ccff00f130468d6c896ef64d10dae0d4754'
)

# setup sqlalchemy
engine = create_engine(DATABASE_URI)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    Base.metadata.create_all(bind=engine)


class User(Base):
    __tablename__ = 'users'
    id = Column('user_id', Integer, primary_key=True)
    first_name = Column(String(60))
    last_name = Column(String(60))
    patient_id = Column(String(60))
    oauth_token = Column(String(200))
    oauth_secret = Column(String(200))

    def __init__(self, name):
        self.name = name


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.after_request
def after_request(response):
    db_session.remove()
    return response


@oyoh.tokengetter
def get_oyoh_token():
    """This is used by the API to look for the auth token and secret
it should use for API calls. During the authorization handshake
a temporary set of token and secret is used, but afterwards this
function has to return the token and secret. If you don't want
to store this in the database, consider putting it into the
session instead.
"""
    return session.get('access_token')
    # user = g.user
    # if user is not None:
        # return user.oauth_token, user.oauth_secret


def get_json(method):
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'Bearer '+access_token}
    req = Request('https://cajuncodefest.dhh.la.gov/api/v1/' + method + '.json',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            return None
        return res.read()

    return res.read()


@app.route('/')
def index():
    res = get_json('me')
    if res is not None:
        return res
    else:
        session.pop('access_token', None)
        return redirect(url_for('login'))



@app.route('/login')
def login():
    """Calling into authorize will cause the OpenID auth machinery to kick
in. When all worked out as expected, the remote application will
redirect back to the callback URL provided.
"""
    return oyoh.authorize(callback='http://localhost:5000/oauth-authorized')
    # return oyoh.authorize(callback=url_for('oauth_authorized',
    #     next=request.args.get('next') or request.referrer or None))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You were signed out')
    return redirect(request.referrer or url_for('index'))


@app.route('/oauth-authorized')
@oyoh.authorized_handler
def oauth_authorized(resp):
    """Called after authorization. After this function finished handling,
the OAuth information is removed from the session again. When this
happened, the tokengetter from above is used to retrieve the oauth
token and secret.

Because the remote application could have re-authorized the application
it is necessary to update the values in the database.

If the application redirected back after denying, the response passed
to the function will be `None`. Otherwise a dictionary with the values
the application submitted. Note that oyoh itself does not really
redirect back unless the user clicks on the application name.
"""
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)

    access_token = resp['access_token']
    session['access_token'] = access_token, ''

    me = oyoh.get('/me')

    return redirect(url_for('index'))

    user = User.query.filter_by(id=resp['user_id']).first()

    # user never signed on
    if user is None:
        user = User(resp['screen_name'])
        db_session.add(user)

    # in any case we update the authenciation token in the db
    # In case the user temporarily revoked access we will have
    # new tokens here.
    user.oauth_token = resp['oauth_token']
    user.oauth_secret = resp['oauth_token_secret']
    db_session.commit()

    session['user_id'] = user.id
    # flash('You were signed in')
    return redirect(next_url)


if __name__ == '__main__':
    app.run()


