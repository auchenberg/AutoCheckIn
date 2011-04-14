from google.appengine.ext import db
from google.appengine.api import users
from google.appengine.api.labs import taskqueue
from appengine_utilities import sessions
from flask import Module, g, redirect, render_template, request, url_for

import logging
import oauth2 as oauth

from autocheckin import settings, oauth_helper
from autocheckin.clients import foursquare
from autocheckin.data import UserRepository, LocationRepository, ServiceRepository

auth = Module(__name__)
session = sessions.Session()

@auth.route('/profile/setup/<service>')
def service_auth(service):
    userProfile = UserRepository.get(users.get_current_user()) 
    
    if(ServiceRepository.get(service, userProfile) != None):
        return redirect(url_for('profile.profile_index'))
    
    callback_url = 'http://autocheckin.appspot.com/profile/setup/' + service + '/authorized'
    
    if(settings.isDebug):
        callback_url = 'http://localhost:8080/profile/setup/' + service + '/authorized' 

    if service == 'latitude':
        consumer = oauth.Consumer(settings.latitude_key, settings.latitude_secret)
        request_token_url = settings.latitude_request_token_url
        authorize_base_url = settings.latitude_authorize_url
        session_key = 'oauth_latitude_request_secret'
    if service == 'foursquare':
        consumer = oauth.Consumer(settings.foursquare_key, settings.foursquare_secret)
        request_token_url = settings.foursquare_request_token_url
        authorize_base_url = settings.foursquare_authorize_url
        session_key = 'oauth_foursquare_request_secret'
    
    helper = oauth_helper.OAuthHelper(consumer)    
    request_token = helper.get_request_token(request_token_url, callback_url)
    authorize_url = helper.get_authorize_url(request_token, authorize_base_url)

    session[session_key] = request_token.secret

    return redirect(authorize_url)

@auth.route('/profile/setup/<service>/authorized')
def oauth_authorized(service):
 
    if service == 'latitude':   
        consumer = oauth.Consumer(settings.latitude_key, settings.latitude_secret)
        request_secret = session['oauth_latitude_request_secret']
        access_token_url = settings.latitude_access_token_url
    if service == 'foursquare':
        consumer = oauth.Consumer(settings.foursquare_key, settings.foursquare_secret)
        request_secret = session['oauth_foursquare_request_secret']
        access_token_url = settings.foursquare_access_token_url
    
    userProfile = UserRepository.get(users.get_current_user()) 
    helper = oauth_helper.OAuthHelper(consumer)    
    token = oauth.Token(request.args.get('oauth_token'), request_secret)
    verifier = request.args.get('oauth_verifier')
    access_token = helper.get_access_token(token, verifier, access_token_url)

    ServiceRepository.new(userProfile, service, access_token.key, access_token.secret)

    return redirect(url_for('profile.profile_index'))
