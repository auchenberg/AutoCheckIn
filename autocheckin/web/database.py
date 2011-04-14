from google.appengine.ext import webapp
from google.appengine.api.labs import taskqueue
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.api import users
from flask import Module, g, redirect, render_template, request
import logging
import simplejson as json
import oauth2 as oauth

from autocheckin import data, settings, oauth_helper
from autocheckin.clients import foursquare

database = Module(__name__)


@database.route('/db/delete-location', methods=['GET'])
def delete_location():
    q = db.GqlQuery("SELECT * FROM Location")    
    for result in q:
        result.delete()
    
    return "Whiped"

@database.route('/db/enable-users', methods=['GET'])    
def enable_users():
    q = db.GqlQuery("SELECT * FROM User")    
    for result in q:
        result.isPaused = False
        result.put()

    return "All users enabled"

