#!/usr/bin/env python
# vim:fileencoding=UTF-8:ts=4:sw=4:sta:et:sts=4:fdm=marker:ai
from flask import Flask, request, redirect, url_for, session, flash, g, \
     render_template
from flask_oauth import OAuth

# configuration
SECRET_KEY = 'development key'
DEBUG = True

# setup flask
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

# Use oyoh as example remote application
oyoh = oauth.remote_app('oyoh',
    base_url='https://cajuncodefest.dhh.la.gov/api/v1/',
    request_token_url=None,
    access_token_url='https://cajuncodefest.dhh.la.gov/oauth/token',
    access_token_method='POST',
    request_token_params={'response_type': 'code'},
    access_token_params={'grant_type': 'authorization_code'},
    authorize_url='https://cajuncodefest.dhh.la.gov/oauth/authorize',
    consumer_key='c7222ef96c60119bbf2b394a7c460a56a13c4e5b01ab9a394d63fb1c23106f65',
    consumer_secret='bc2180403617de236264a08039948ccff00f130468d6c896ef64d10dae0d4754'
)


@oyoh.tokengetter
def get_oyoh_token():
    return session.get('access_token')

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
    return oyoh.authorize(callback='http://localhost:5000/oauth-authorized')
    # return oyoh.authorize(callback=url_for('oauth_authorized',
    #     next=request.args.get('next') or request.referrer or None))


@app.route('/oauth-authorized')
@oyoh.authorized_handler
def oauth_authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''

    me = oyoh.get('/me')

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()


