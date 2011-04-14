import sys, os
import httplib
import logging
import time

from flask import Flask
app = Flask(__name__)

from flaskext.oauth import OAuth

from google.appengine.ext import db
from google.appengine.api import users

from flask import redirect, session, url_for, request, render_template, abort, flash

oauth = OAuth()

# Use Twitter as example remote application
# Use Twitter as example remote application
twitter = oauth.remote_app('twitter',
    # unless absolute urls are used to make requests, this will be added
    # before all URLs.  This is also true for request_token_url and others.
    base_url='http://api.twitter.com/1/',
    # where flask should look for new request tokens
    request_token_url='http://api.twitter.com/oauth/request_token',
    # where flask should exchange the token with the remote application
    access_token_url='http://api.twitter.com/oauth/access_token',
    # twitter knows two authorizatiom URLs.  /authorize and /authenticate.
    # they mostly work the same, but for sign on /authenticate is
    # expected because this will give the user a slightly different
    # user interface on the twitter side.
    authorize_url='http://api.twitter.com/oauth/authenticate',
    # the consumer keys from the twitter application registry.
    consumer_key='xBeXxg9lyElUgwZT6AZ0A',
    consumer_secret='aawnSpNTOVuDCjx7HMh6uSXetjNN8zWLpZwCEU4LBrk'
)

class ServiceAuth(db.Model): 
	user = db.UserProperty()
	service = db.StringProperty(required=True)
	access_token = db.StringProperty(required=True)
	access_secret = db.StringProperty(required=True)


@twitter.tokengetter
def get_twitter_token():
    """This is used by the API to look for the auth token and secret
    it should use for API calls.  During the authorization handshake
    a temporary set of token and secret is used, but afterwards this
    function has to return the token and secret.  If you don't want
    to store this in the database, consider putting it into the
    session instead.
    """
    return None




@app.route('/')

def index():
    user = users.get_current_user()
    services = ServiceAuth.all().filter('user =', user)
    return render_template('list.html', user=user, logout_url=users.create_logout_url("/"), tasks=services);

@app.route('/', methods=['POST'])
def add_service():
    service = request.form['service']
    token = request.form['token']
    secret = request.form['secret']

    serviceAuth = ServiceAuth(service = service, access_token=token, access_secret=secret)
    serviceAuth.user = users.get_current_user()
    serviceAuth.put()

    return redirect(url_for('list'))

@app.route('/auth')
def service_auth(service):
    return twitter.authorize(callback='http://localhost:8080/oauth-authorized')

@app.route('/oauth-authorized')
@twitter.authorized_handler
def oauth_authorized(resp):

    return "Done"
    
    
if __name__ == '__main__':
    app.run()
