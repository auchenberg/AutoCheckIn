#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Third party libraries
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

# Settings
import settings

# Standard python modules
import cgi
import datetime
import hashlib
import logging
import os
import string
import sys
import time
import urllib
import uuid

# Appengine sdk
from google.appengine.api import urlfetch
from google.appengine.ext import db
from google.appengine.ext.db import polymodel
from google.appengine.api import memcache
from google.appengine.api import users
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.ext.webapp import template
from google.appengine.api.labs import taskqueue

# Appengine provided third party libs
from django.utils import simplejson as json
from wsgiref import handlers

# Local modules
import foursquare
import latitude

# Third party (/lib) modules
import oauth
import oauth_appengine
import sessions

# SETTINGS

GOOGLE_CONSUMER_KEY = 'latisquare.kenneth.io'
GOOGLE_CONSUMER_SECRET = 'vzzg2adpLYAAFXtGmVHP0See'
FOURSQUARE_CONSUMER_KEY = 'FR2XN3L4NX4OSBQDAGHF44MVBJYBW5FMAOKEMLSTRC03RBIR'
FOURSQUARE_CONSUMER_SECRET = 'T25QTO2W25VNOROO5WOXAOI4BZDRTZGWA4QJ4CEWMCG2KJLD'


def foursquareClient(service):
  access_token = oauth_appengine.OAuthToken.toRealOAuthToken(service.access_token)

  # Construct client
  oauth_client = foursquare.FoursquareOAuthClient(oauth_consumer=oauth.OAuthConsumer(FOURSQUARE_CONSUMER_KEY, 
																					FOURSQUARE_CONSUMER_SECRET), oauth_token=access_token)
  return foursquare.Foursquare(oauth_client)


def latitudeClient(service):
  access_token = oauth_appengine.OAuthToken.toRealOAuthToken(
      service.access_token)

  # Construct client
  oauth_client = latitude.LatitudeOAuthClient(
      oauth_consumer=oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
          GOOGLE_CONSUMER_SECRET),
      oauth_token=access_token)
  return latitude.Latitude(oauth_client)


class MainHandler(webapp.RequestHandler):

  def get(self, mode=""):
    

    application_key = "FILL_IN" 
    application_secret = "FILL_IN"  
    
    user_token = "FILL_IN"  
    user_secret = "FILL_IN"
    
    callback_url = "%s/verify" % self.request.host_url
    
    client = oauth.TwitterClient(application_key, application_secret, callback_url)
    
    if mode == "login":
      return self.redirect(client.get_authorization_url())
      
    self.response.out.write("<a href='/login'>Login via Twitter</a>")

def main():
  application = webapp.WSGIApplication([('/(.*)', MainHandler)], debug=True)
  util.run_wsgi_app(application)


if __name__ == '__main__':
  main()