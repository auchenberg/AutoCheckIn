#!/usr/bin/env python
#
# Copyright 2008 Google Inc.
# Copyright 2010 Joe LaPenna
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

"""Main entrypoint for a latitude mashup."""

# Third party libraries
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'private'))
sys.path.insert(0,
    os.path.join(os.path.dirname(__file__), 'lib/appengine_utilities'))

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
import buzz_oauth_client
import foursquare
import latitude
import places

# Third party (/lib) modules
import buzz
import oauth
import oauth_appengine
import sessions


# SETTINGS


DEBUG = settings.DEBUG
FETCH_MAX = settings.FETCH_MAX
GOOGLE_CONSUMER_KEY = settings.GOOGLE_CONSUMER_KEY
GOOGLE_CONSUMER_SECRET = settings.GOOGLE_CONSUMER_SECRET
FOURSQUARE_CONSUMER_KEY = settings.FOURSQUARE_CONSUMER_KEY
FOURSQUARE_CONSUMER_SECRET = settings.FOURSQUARE_CONSUMER_SECRET
PLACES_CLIENT_ID = settings.PLACES_CLIENT_ID
PLACES_KEY = settings.PLACES_KEY


# PATHS


PROFILE_PATH = '/profile/%s'
START_PATH = '/start'
HOME_PATH = '/home'
NEARBY_PATH = '/nearby'
NEARBYJS_PATH = '/nearbyjs'
MATCH_PATH = '/match'

BUZZ_OAUTH_START_PATH = '/buzz_oauth_start'
BUZZ_OAUTH_CALLBACK_PATH = '/buzz_oauth'
BUZZ_PATH = '/buzz'
BUZZ_POST_TASK_PATH = '/task/buzz_post'

FOURSQUARE_OAUTH_START_PATH = '/foursquare_oauth_start'
FOURSQUARE_OAUTH_CALLBACK_PATH = '/foursquare_oauth'
FOURSQUARE_PATH = '/foursquare'

FOURSQUARE_FETCH_PATH = '/foursquare_fetch'
FOURSQUARE_FETCH_TASK_PATH = '/task/foursquare_fetch'

FOURSQUARE_MATCH_VENUE_PATH = '/foursquare_match_venue'
FOURSQUARE_MATCH_VENUE_TASK_PATH = '/task/foursquare_match_venue'

FOURSQUARE_VENUE_CACHE_TASK_PATH = '/task/foursquare_venue_cache'

LATITUDE_OAUTH_START_PATH = '/latitude_oauth_start'
LATITUDE_OAUTH_CALLBACK_PATH = '/latitude_oauth'
LATITUDE_PATH = '/latitude'

PLACES_PATH = '/placesrpc'


# OTHER CONSTANTS

STOP_WORDS = ('a', 'an', 'and', 'are', 'as', 'at', 'be', 'but', 'by', 'for',
              'if', 'in', 'into', 'is', 'it', 'no', 'not', 'of', 'on', 'or',
              'such', 'that', 'the', 'their', 'then', 'there', 'these', 'they',
              'this', 'to', 'was', 'will', 'with')


# EXCEPTIONS


class Error(Exception):
  """Module level error."""


class ServiceError(Error):
  """Raised when a service does not exit for a user."""


# MODEL


class User(db.Model):
  """A user that owns feeds we proxy."""

  # Google-provided user info.
  google_user = db.UserProperty(auto_current_user=True)

  # Profile hash for profile url.
  profile_hash = db.StringProperty()

  # Web session
  session = db.ReferenceProperty(sessions._AppEngineUtilities_Session)

  def cacheService(self, session, service_name, service, cacheInMemcache=True,
      cacheInSession=True):
    if memcache:
      memcache_hash = '%s_%s' % (self.key, service_name)
      memcache.add(memcache_hash, service)
    if session:
      session[service_name] = service

  def findService(self, session, service_name):
    memcache_hash = '%s_%s' % (self.key, service_name)
    service = None

    # Try a memcache lookup before hitting the datastore.
    if session:
      service = memcache.get(memcache_hash)

    # Try a session lookup before doing a heavy-duty lookup.
    if service is None and session:
      service = session[service_name]
      if service:
        self.cacheService(session, service_name, service, cacheInSession=False)

    # Look it up manually if necessary.
    if service is None:
      query = (Service.all()
          .ancestor(self)
          .filter('name =', service_name))

      # Assert we get the right kind of result.
      count = query.count()
      if count < 1:
        raise ServiceError(
          'Unable to lookup service instance for: %s' % service_name)

      elif count > 1:
        raise ServiceError(
          'Too many query for name: %s' % service_name)

      service = query.get()
      self.cacheService(session, service_name, service)

    # If we can't find it, raise an exception
    if not service:
      raise ServiceError(
        'Unable to lookup service instance for: %s' % service_name)
    else:
      return service

  @classmethod
  def memcachedUser(cls, user_id):
    hash = 'user_' + user_id
    data = memcache.get(key)
    if data is None:
      data = User.get_by_key_name(user_id)


class Service(db.Model):
  """A service that has access tokens."""

  # The user owning this service.
  user = db.ReferenceProperty(User)

  # Auth Token to access protected URLs for this service.
  access_token = db.ReferenceProperty(oauth_appengine.OAuthToken)

  # The name of the service.
  name = db.StringProperty()


class Activity(polymodel.PolyModel):
  """An activity in a service by a user."""

  # When the service record was last modified.
  updated = db.DateTimeProperty(auto_now=True)


class BuzzActivity(Activity):
  """A buzz activity created by a user."""

  # The identifier of the post this entity represents.
  post_id = db.StringProperty()

  # Unparsed post data, per the buzz docs.
  post_json = db.TextProperty()


class FoursquareActivity(Activity):
  """A foursquare checkin created by a user."""

  # The foursquare-provided id of this checkin.
  checkin_id = db.StringProperty()

  # Unparsed checkin data, per the foursquare docs.
  checkin_json = db.TextProperty()

  # A buzz post that was created for this activity.
  #buzz_activity = db.ReferenceKey(BuzzActivity)


class ServiceRecord(polymodel.PolyModel):
  """A record describing the state of a service."""

  # When the service record was last modified.
  updated = db.DateTimeProperty(auto_now=True)

  # If there is a task operating on this service record.
  active = db.BooleanProperty(default=False)

  @classmethod
  def lock(cls, service):
    """Find a service record and lock it."""
    query = ServiceRecord.all().ancestor(service)
    service_record_container = []
    def txn():
      # Find a service record or create one to put.
      if (query.count() == 0):
        service_record = cls(parent=service)
      elif (query.count() == 1):
        service_record = query.get()
      else:
        raise Error('Unexpected result size for stream record query')

      # Verify we're not getting an already active service record.
      if service_record.active:
        raise Error('service record %s already active' % service_record)

      # Update and put the record.
      service_record.active = True;
      service_record.put()
      service_record_container.append(service_record)
    db.run_in_transaction(txn)
    return service_record_container[0]


class FoursquareServiceRecord(ServiceRecord):
  """A record describing a foursquare user's state."""

  # The last history record retrieved from a user's history.
  sinceid = db.StringProperty()


class Venue(db.Model):
  """Store information about a venue."""
  id = db.StringProperty()
  name = db.StringProperty()
  address = db.StringProperty()
  city = db.StringProperty()
  state = db.StringProperty()
  zip = db.StringProperty()
  phone = db.StringProperty()
  geolat = db.StringProperty()
  geolong = db.StringProperty()

  # Unparsed venue data, per the foursquare service docs.
  json = db.TextProperty()

  # If true, place_json is set.
  place_exists = db.BooleanProperty(default=False)

  # Unparsed places API data, per the places web service docs.
  place_json = db.TextProperty()

  # If place_json is set, when it was set (or skipped, if no place was found).
  place_updated = db.DateTimeProperty()


  # Keys automagically populated from the josn we're caching.
  KEYS = ['id', 'name', 'address', 'city', 'state', 'zip', 'phone', 'geolat',
      'geolong']

  def set_place(self, place_json):
    """Set the place and accompanying fields for filters."""
    self.place_json = place_json
    self.place_updated = datetime.datetime.now()
    self.place_exists = bool(place_json)

  @classmethod
  def put_json(cls, json_string):
    """Cache a venue or a set of venues in our datastore."""
    parsed = json.loads(json_string)

    venues = []
    if 'groups' in parsed:
      for group in parsed['groups']:
        venues.extend(group['venues'])
    else:
      venues.append(parsed)

    models = []
    for venue in venues:
      model_dict = dict((str(k), str(v))
                         for k, v in venue.iteritems() if k in Venue.KEYS)
      model_dict['key_name'] = salted_hash('foursquare_venue', venue['id'])
      model_dict['json'] = json.dumps(venue)
      models.append(model_dict)
    db.put([Venue(**model) for model in models])


# HELPER CLASSES

class VenueMatcher(object):
  """Match a Foursquare Venue with a Place."""

  class Match(object):
    venue = None
    places_list = None
    details_list = None
    html_attributions = None
    place = None

  @classmethod
  def match(cls, venue, places_list=None, details_list=None):
    """Return an object with match information."""
    match = VenueMatcher.Match()
    match.venue = venue

    if places_list is not None:
      match.places_list = places_list
    if details_list is not None:
      match.details_list = details_list

    if match.places_list is None:
      match.places_list, match.html_attributions = VenueMatcher._get_places(
          match.venue['geolat'], match.venue['geolong'])

    if match.details_list is None:
      match.details_list, match.html_attributions = (
          VenueMatcher._get_places_details(match.places_list))

    match.place = VenueMatcher._match_venue(match.venue, match.details_list)
    return match

  @classmethod
  def _get_places(cls, latitude, longitude):
    """Find all the places near a given latitude and longitude."""
    places_client = places.Places(PLACES_CLIENT_ID, PLACES_KEY)
    # TODO: radius based on lat/long precision
    response = places_client.placeSearch(
        latitude=latitude,
        longitude=longitude,
        radius=100,
        sensor='false')
    content = response.content
    search = json.loads(content)
    places_list = search['results']
    html_attribution = search['html_attributions']
    return places_list, html_attribution

  @classmethod
  def _get_places_details(cls, places_list):
    """Get the details of each place in the places list: phone, etc."""
    places_client = places.Places(PLACES_CLIENT_ID, PLACES_KEY)
    details_list = []
    html_attributions = []

    def callback(rpc):
      response = rpc.get_result()
      response_json = json.loads(rpc.get_result().content)
      details_list.append(response_json['result'])
      html_attributions.extend([a for a in response_json['html_attributions']])
    places_client.get_places_details(places_client, places_list,
        callback=callback)
    return details_list, html_attributions

  @classmethod
  def _normalize_phone(cls, phone):
    """Strip all non-digit characters from a number."""
    if phone is None:
      return None
    normalized_phone = ''
    for digit in phone:
      if digit.isdigit():
        normalized_phone += digit
    return normalized_phone or None

  @classmethod
  def _match_venue(cls, venue, details_list):
    """Find a  match for venue from details_list."""
    place_match = None

    # Compare the stripped phone number of the venue to each place in the
    # details list. If they match, consider the venue a match.
    foursquare_venue_phone = VenueMatcher._normalize_phone(venue.get('phone'))
    if foursquare_venue_phone is not None:
      for place in details_list:
        phone = VenueMatcher._normalize_phone(
            place.get('formatted_phone_number'))
        if (phone is not None) and (phone == foursquare_venue_phone):
          place_match = place
    return place_match


# HELPERS


def mkurl(request, path, *args):
  return (request.host_url + path) % args


def random_hash(value):
  """Hash that cannot be matched value."""
  return salted_hash(uuid.uuid4().get_hex(), value)


def salted_hash(salt, value):
  """Hash that can be matched by calling this with the same salt and value"""
  return sha1_hash('%s_%s' % (salt, value))


def sha1_hash(value):
  """Returns the sha1 hash of the supplied value."""
  return hashlib.sha1(utf8encoded(value)).hexdigest()


def utf8encoded(data):
  """Encodes a string as utf-8 data and returns an ascii string.

  Args:
    data: The string data to encode.

  Returns:
    An ascii string, or None if the 'data' parameter was None.
  """
  if data is None:
    return None
  if isinstance(data, unicode):
    return unicode(data).encode('utf-8')
  else:
    return data


def buzzClient(service):
  client = buzz.Client()
  client.oauth_consumer = oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
      GOOGLE_CONSUMER_SECRET)
  client.oauth_access_token = oauth_appengine.OAuthToken.toRealOAuthToken(
      service.access_token)
  return client


def foursquareClient(service):
  access_token = oauth_appengine.OAuthToken.toRealOAuthToken(
      service.access_token)

  # Construct client
  oauth_client = foursquare.FoursquareOAuthClient(
      oauth_consumer=oauth.OAuthConsumer(FOURSQUARE_CONSUMER_KEY,
          FOURSQUARE_CONSUMER_SECRET),
      oauth_token=access_token)
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


# DECORATORS


def login_required(handler_method):
  """A decorator to require that a user be logged in to access a handler.

  To use it, decorate your get() method like this:

    @login_required
    def get(self):
      user = users.get_current_user(self)
      self.response.out.write('Hello, ' + user.nickname())

  We will redirect to a login page if the user is not logged in. We always
  redirect to the request URI, and Google Accounts only redirects back as a GET
  request, so this should not be used for POSTs.
  """
  def check_login(self, *args, **kwargs):
    logging.debug('check_login')
    if self.request.method != 'GET':
      raise webapp.Error('The check_login decorator can only be used for GET '
                         'requests')
    google_user = users.get_current_user()
    if not google_user:
      logging.debug('check_login: redirecting user')
      self.redirect(users.create_login_url(self.request.uri))
      return
    else:
      logging.debug('check_login: loading user')
      user = User.get_by_key_name(google_user.user_id())
      session = sessions.Session()
      if user is None:
        profile_hash = random_hash(google_user.user_id())
        user = User(key_name=google_user.user_id(),
                    google_user=google_user,
                    profile_hash=profile_hash)
        user.put()
      kwargs.update({'user': user, 'session': session})
      handler_method(self, *args, **kwargs)
  return check_login


def referer_required(handler_method):
  """A decorator to require that a request come from a local referer.

  To use it, decorate your get() method like this:

    @referer_required
    def get(self):
      pass

  We will 401 on an unauthorized request.
  """
  def check_referer(self, *args, **kwargs):
    logging.debug('check_referer')
    referer = self.request.referer
    valid_referer = (referer is not None
                     and referer.startswith(self.request.host_url))
    if valid_referer:
      handler_method(self, *args, **kwargs)
    else:
      self.response.clear()
      self.response.set_status(401)
  return check_referer


def work_queue_only(func):
  """Decorator that only allows a request if from cron job, task, or an admin.

  Also allows access if running in development server environment.

  Args:
    func: A webapp.RequestHandler method.

  Returns:
    Function that will return a 401 error if not from an authorized source.
  """
  def decorated(myself, *args, **kwargs):
    if ('X-AppEngine-Cron' in myself.request.headers or
        'X-AppEngine-TaskName' in myself.request.headers or
        'Dev' in os.environ.get('SERVER_SOFTWARE', '') or
        users.is_current_user_admin()):
      return func(myself, *args, **kwargs)
    elif users.get_current_user() is None:
      myself.redirect(users.create_login_url(myself.request.url))
    else:
      myself.response.set_status(401)
      myself.response.out.write('Handler only accessible for work queues')
  return decorated


# HANDLERS


class StartHandler(webapp.RequestHandler):
  """Starts the registration process."""

  @login_required
  def get(self, user=None, session=None):
    service_name = self.request.get('service_name', None)
    next = self.request.get('next', None)

    url = None

    # First try and handle a specified service name.

    if service_name == 'buzz':
      url = mkurl(self.request, BUZZ_OAUTH_START_PATH)

    elif service_name == 'foursquare':
      url = mkurl(self.request, FOURSQUARE_OAUTH_START_PATH)

    elif service_name == 'latitude':
      url = mkurl(self.request, LATITUDE_OAUTH_START_PATH)

    # Then handle invalid service names

    elif service_name is not None:
      self.response.clear()
      self.response.set_status(404)

    # Then handle the auth workflow

    else:
      services = set()
      for service in Service.all(keys_only=True).ancestor(user):
        services.add(service.name)

      has_buzz = 'buzz' in services
      has_latitude = 'latitude' in services
      has_foursquare = 'foursquare' in services

      # If we have all services, just go home.
      if has_buzz and has_latitude and has_foursquare:
        url = mkurl(self.request, HOME_PATH)
      else:
        if not has_buzz:
          url = mkurl(self.request, BUZZ_OAUTH_START_PATH)
        elif not has_foursquare:
          url = mkurl(self.request, FOURSQUARE_OAUTH_START_PATH)
        elif not has_latitude:
          url = mkurl(self.request, LATITUDE_OAUTH_START_PATH)
        else:
          url = mkurl(self.request, HOME_PATH)

    # Redirect the user based on workflow.
    if url:
      logging.info('Redirecting from %s to %s' % (self.request.path, url))
      self.redirect(url)


class OAuthStartHandler(webapp.RequestHandler):
  """Starts the oAuth process.

  Gets a temporary auth token and redirecting the user to the service's login
  handler.
  """

  def initialize(self, request, response):
    super(OAuthStartHandler, self).initialize(request, response)
    self.service_name = None
    self.oauth_client = None
    self.callback_path = None
    self.parameters = {}

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: OAuthStartHandler (%s)' % self.service_name)

    try:
      service = user.findService(session, self.service_name)
    except ServiceError, e:
      service = Service(parent=user, user=user, name=self.service_name)

    # Request a request token
    helper = oauth_appengine.OAuthDanceHelper(self.oauth_client)
    request_token = helper.RequestRequestToken(
        mkurl(self.request, self.callback_path),
        parameters=self.parameters)

    # Save for later
    oauth_request_token = oauth_appengine.OAuthToken.fromOAuthToken(
        request_token)
    service.access_token = oauth_request_token.put()
    logging.debug('Putting service: %s/%s' % (self.service_name, service.name))
    service.put()

    # Redirect user
    url = helper.GetAuthorizationRedirectUrl(request_token,
        callback=mkurl(self.request, self.callback_path),
        parameters=self.parameters)
    logging.debug('Redirect: %s' % url)
    self.redirect(url)


class OAuthCallbackHandler(webapp.RequestHandler):
  """After the user logs into the target service, they're redirected here.

  On successful lookup, will store the user's auth token in their session.
  """

  def initialize(self, request, response):
    super(OAuthCallbackHandler, self).initialize(request, response)
    self.service_name = None
    self.oauth_client = None
    self.redirect_path = None

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: OAuthCallbackHandler (%s)' % self.service_name)

    logging.debug('Query String: ' + self.request.query_string)

    service = user.findService(session, self.service_name)

    request_token = oauth_appengine.OAuthToken.toRealOAuthToken(
        service.access_token)

    # Hold a refrence to the temporary request token entity, to delete later.
    request_token_entity = service.access_token

    # Find the key from the request and pull it from the datastore/memcache
    key_name = self.request.get('oauth_token', None)
    verifier = self.request.get('oauth_verifier', None)

    # Request a token that we can use to access resources.
    helper = oauth_appengine.OAuthDanceHelper(self.oauth_client)
    access_token = helper.RequestAccessToken(request_token, verifier=verifier)

    # Save it for later
    oauth_access_token = oauth_appengine.OAuthToken.fromOAuthToken(access_token)
    service.access_token = oauth_access_token.put()
    logging.debug('Putting service: %s/%s' % (self.service_name, service.name))
    service.put()

    # Delete the old access token.
    request_token_entity.delete()

    # Redirect user
    url = mkurl(self.request, self.redirect_path)
    logging.debug('Redirect: %s' % url)
    self.redirect(url)


class BuzzOAuthStartHandler(OAuthStartHandler):
  """Starts the oAuth process for buzz."""

  def initialize(self, request, response):
    super(BuzzOAuthStartHandler, self).initialize(request, response)
    self.service_name = 'buzz'
    self.oauth_client = buzz_oauth_client.BuzzOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
            GOOGLE_CONSUMER_SECRET))
    self.callback_path = BUZZ_OAUTH_CALLBACK_PATH + '?service=buzz'
    self.parameters = {'scope': buzz_oauth_client.BuzzOAuthClient.SCOPE,
                       'domain': GOOGLE_CONSUMER_KEY,}


class BuzzOAuthCallbackHandler(OAuthCallbackHandler):
  """After the user logs into buzz, they're redirected here."""

  def initialize(self, request, response):
    super(BuzzOAuthCallbackHandler, self).initialize(request, response)
    self.service_name = 'buzz'
    self.oauth_client = buzz_oauth_client.BuzzOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
            GOOGLE_CONSUMER_SECRET))
    self.redirect_path = START_PATH


class FoursquareOAuthStartHandler(OAuthStartHandler):
  """Starts the oAuth process for foursquare."""

  def initialize(self, request, response):
    super(FoursquareOAuthStartHandler, self).initialize(request, response)
    self.service_name = 'foursquare'
    self.oauth_client = foursquare.FoursquareOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(FOURSQUARE_CONSUMER_KEY,
            FOURSQUARE_CONSUMER_SECRET))
    self.callback_path = FOURSQUARE_OAUTH_CALLBACK_PATH


class FoursquareOAuthCallbackHandler(OAuthCallbackHandler):
  """After the user logs into foursquare, they're redirected here."""

  def initialize(self, request, response):
    super(FoursquareOAuthCallbackHandler, self).initialize(request, response)
    self.service_name = 'foursquare'
    self.oauth_client = foursquare.FoursquareOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(FOURSQUARE_CONSUMER_KEY,
            FOURSQUARE_CONSUMER_SECRET))
    self.redirect_path = START_PATH


class LatitudeOAuthStartHandler(OAuthStartHandler):
  """Starts the oAuth process for latitude."""

  def initialize(self, request, response):
    super(LatitudeOAuthStartHandler, self).initialize(request, response)
    self.service_name = 'latitude'
    self.oauth_client = latitude.LatitudeOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
            GOOGLE_CONSUMER_SECRET))
    self.callback_path = LATITUDE_OAUTH_CALLBACK_PATH + '?service=latitude'
    self.parameters = {'scope': latitude.LatitudeOAuthClient.SCOPE,
                       'domain': GOOGLE_CONSUMER_KEY,
                       'granularity': 'best',
                       'location': 'all',}


class LatitudeOAuthCallbackHandler(OAuthCallbackHandler):
  """After the user logs into latitude, they're redirected here."""

  def initialize(self, request, response):
    super(LatitudeOAuthCallbackHandler, self).initialize(request, response)
    self.service_name = 'latitude'
    self.oauth_client = latitude.LatitudeOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
            GOOGLE_CONSUMER_SECRET))
    self.redirect_path = START_PATH


class HomeHandler(webapp.RequestHandler):
  """Show details about a user."""

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: HomeHandler')
    expected_services = ['buzz', 'foursquare', 'latitude']
    services = []

    for service in Service.all().ancestor(user):
      services.append(service.name)
      if service.name in expected_services:
        expected_services.remove(service.name)

    context = {
        # layout.html
        'host_url': self.request.host_url,
        'user': user,
        # home.html
        'services': services,
        'expected_services': expected_services,
    }
    self.response.out.write(template.render('templates/home.html', context))


class NearbyHandler(webapp.RequestHandler):
  """Show information near a user user."""

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: NearbyHandler')

    location = self.get_latitude(user, session)
    checkin, venues = self.get_foursquare(user, session, location)
    buzzes = self.get_buzz(user, session, location)
    places_list, attributions = self.get_places(user, session, location)
    details_list, attributions = self.get_places_details(places_list)

    # Try and match each venue in the list.
    venues_list = []
    for group in venues['groups']:
      venues_list.extend(group['venues'])
    matches = []
    for venue in venues_list:
      match = VenueMatcher.match(venue, places_list=places_list,
          details_list=details_list)
      matches.append((venue, match.place))

    # Cache the venues
    FoursquareVenueCacheTask.add(venues)

    context = {
        # layout.html
        'host_url': self.request.host_url,
        'user': user,
        # nearby.html
        'location': location,
        'checkin': checkin,
        'venues': venues,
        'buzzes': buzzes,
        'places': places_list,
        'matches': matches,
    }
    self.response.out.write(template.render('templates/nearby.html', context))

  def get_latitude(self, user, session):
    latitude_client = latitudeClient(user.findService(session, 'latitude'))
    response = latitude_client.currentLocation()
    content = response.content
    current = json.loads(content)
    return current['data']

  def get_foursquare(self, user, session, location):
    foursquare_client = foursquareClient(
        user.findService(session, 'foursquare'))
    foursquare_user = json.loads(foursquare_client.user().content)
    checkin = foursquare_user['user']['checkin']
    venues = json.loads(foursquare_client.venues(location['latitude'],
        location['longitude']).content)
    return checkin, venues

  def get_buzz(self, user, session, location):
    buzz_client = buzzClient(user.findService(session, 'buzz'))
    result = buzz_client.search(
        latitude=str(location['latitude']),
        longitude=str(location['longitude']),
        radius='100')
    buzzes = []
    for i, b in enumerate(result):
      if i >= 10:
        break
      buzzes.append(b)
    return buzzes

  def get_places(self, user, session, location):
    places_client = places.Places(PLACES_CLIENT_ID, PLACES_KEY)
    response = places_client.placeSearch(
        latitude=location['latitude'],
        longitude=location['longitude'],
        radius=100,
        sensor='false')
    content = response.content
    search = json.loads(content)
    places_list = search['results']
    html_attribution = search['html_attributions']
    return places_list, html_attribution

  def get_places_details(self, places_list):
    """Get the details of each place in the places list: phone, etc."""
    places_client = places.Places(PLACES_CLIENT_ID, PLACES_KEY)
    details_list = []
    html_attributions = []

    def callback(rpc):
      response = rpc.get_result()
      response_json = json.loads(rpc.get_result().content)
      details_list.append(response_json['result'])
      html_attributions.extend([a for a in response_json['html_attributions']])
    places_client.get_places_details(places_client, places_list,
        callback=callback)
    return details_list, html_attributions


class NearbyJsHandler(webapp.RequestHandler):

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: NearbyJsHandler')
    self.response.out.write(template.render('templates/nearby_js.html', {}))


class BuzzRpcHandler(webapp.RequestHandler):
  """Proxy a buzz API request.

  TODO(jlapenna): Think about what sort of abuses can come of this.
    -Reduce xsrfs by checking referer. [DONE]
    -Verify session
  """

  @referer_required
  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: BuzzRpcHandler')

    op = self.request.get('OP')

    client = buzzClient(user.findService(session,'buzz'))

    if op == 'search':
      response = buzz_client.search(
          latitude=self.request.get('latitude'),
          longitude=self.request.get('longitude'),
          radius=self.request.get('radius'),
          max_results=self.request.get('max_results'))
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    else:
      self.response.clear()
      self.response.set_status(404)


class FoursquareRpcHandler(webapp.RequestHandler):
  """Proxy a foursquare API request.

  TODO(jlapenna): Think about what sort of abuses can come of this.
    -Reduce xsrfs by checking referer. [DONE]
    -Verify session
  """

  @referer_required
  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: FoursquareRpcHandler')

    op = self.request.get('OP')

    client = foursquareClient(user.findService(session,'foursquare'))

    if op == 'checkin':
      response = foursquare_client.checkin(
          self.request.get('vid'),
          geolat=self.request.get('geolat'),
          geolong=self.request.get('geolong'))
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    elif op == 'user':
      response = client.user()
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    elif op == 'venues':
      response = client.venues(
          location['latitude'], location['longitude'])
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    elif op == 'history':
      response = client.history()
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    else:
      self.response.clear()
      self.response.set_status(404)

  @classmethod
  def foursquareClient(cls, service):
    access_token = oauth_appengine.OAuthToken.toRealOAuthToken(
        service.access_token)

    # Construct client
    oauth_client = foursquare.FoursquareOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(FOURSQUARE_CONSUMER_KEY,
            FOURSQUARE_CONSUMER_SECRET),
        oauth_token=access_token)
    return foursquare.Foursquare(oauth_client)


class LatitudeRpcHandler(webapp.RequestHandler):
  """Proxy a latitude API request.

  TODO(jlapenna): Think about what sort of abuses can come of this.
    -Reduce xsrfs by checking referer. [DONE]
    -Verify session
  """

  @referer_required
  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: LatitudeRpcHandler')

    op = self.request.get('OP')

    if op == 'currentLocation':
      latitude_client = latitudeClient(user.findService(session, 'latitude'))
      response = latitude_client.currentLocation()
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    else:
      self.response.clear()
      self.response.set_status(404)

  def latitudeClient(self, service):
    access_token = oauth_appengine.OAuthToken.toRealOAuthToken(
        service.access_token)

    # Construct client
    oauth_client = latitude.LatitudeOAuthClient(
        oauth_consumer=oauth.OAuthConsumer(GOOGLE_CONSUMER_KEY,
            GOOGLE_CONSUMER_SECRET),
        oauth_token=access_token)
    return latitude.Latitude(oauth_client)


class PlacesRpcHandler(webapp.RequestHandler):
  """Proxy a Places API request.

  TODO(jlapenna): Think about what sort of abuses can come of this.
    -Reduce xsrfs by checking referer. [DONE]
    -Verify session
  """

  @referer_required
  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: PlacesRpcHandler')

    op = self.request.get('OP')

    if op == 'placeSearch':
      places_client = places.Places(None)
      response = places_client.placeSearch(
          latitude=self.request.get('latitude'),
          longitude=self.request.get('longitude'),
          radius=self.request.get('radius'),
          sensor=self.request.get('sensor'))
      self.response.set_status(response.status_code)
      self.response.out.write(response.content)
    else:
      self.response.clear()
      self.response.set_status(404)


class MatchHandler(webapp.RequestHandler):

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: OAuthCallbackHandler')
    venue = self.get_foursquare(user, session, self.request.get('vid'))
    match = VenueMatcher.match(venue)

    # Cache the venues
    FoursquareVenueCacheTask.add(venue)

    context = {
        # layout.html
        'host_url': self.request.host_url,
        'user': user,
        # nearby.html
        'venue': venue,
        'match': match.place,
        'places': match.details_list,
        'html_attributions': match.html_attributions,
    }
    self.response.out.write(template.render('templates/match.html', context))

  def get_foursquare(self, user, session, vid):
    foursquare_client = foursquareClient(
        user.findService(session, 'foursquare'))
    foursquare_venue = json.loads(foursquare_client.venue(vid).content)['venue']
    return foursquare_venue


class BuzzPostTask(webapp.RequestHandler):
  """Handle a buzz post task."""

  SERVICE_PARAM = 'service'
  ACTIVITY_PARAM = 'activity'

  def post(self):
    logging.debug('Handled: BuzzPostTask')

    # Read keys from the query.
    service_encoded = self.request.get(BuzzPostTask.SERVICE_PARAM)
    activity_encoded = self.request.get(BuzzPostTask.ACTIVITY_PARAM)
    if (service_encoded is None or activity_encoded is None):
      self.response.clear()
      self.response.set_status(400, message='Missing required query parameter')
      return

    # Pull the objects from the datastore.
    buzz_service = Service.get(service_encoded)
    activity = Activity.get(activity_encoded)
    if (buzz_service is None or activity is None):
      self.response.clear()
      self.response.set_status(400, message='Unknown service or activity')
      return

    # Parse the activity into a checkin
    checkin = json.loads(activity.checkin_json)
    if not checkin.has_key('venue'):
      return

    # Find the place it might be.
    match = VenueMatcher.match(checkin['venue'])

    # Create a post if the activity is a checkin.
    post = self.construct_post(checkin, match.place)
    if post is not None:
      buzz_client = buzzClient(buzz_service)
      buzz_client.create_post(post)

      # Store that we created a post.
      #buzz_activity = BuzzActivity(parent=buzz_service, post_id=post.id,
      #    post_json=json.dumps(post.json)).put()
      #activity.buzz_activity = buzz_activity
      #activity.put()

  def construct_post(self, checkin, place):
    if not checkin.has_key('venue'):
      return

    if place is not None:
      place_id = place['reference']
    else:
      place_id = None

    content = template.render('templates/buzz_foursquare_post.html',
        {'checkin': checkin})
    attachment = buzz.Attachment(type='article',
        title=checkin['venue']['name'] + ' on Foursquare',
        uri='http://foursquare.com/venue/%s' % checkin['venue']['id'])
    post = buzz.Post(content=content,
        geocode=(checkin['venue']['geolat'], checkin['venue']['geolong']),
        attachments=[attachment], place_id=place_id)
    return post


class FoursquareFetchTask(webapp.RequestHandler):
  """Handle a foursquare fetch task."""

  SERVICE_PARAM = 'service'
  SERVICE_RECORD_PARAM = 'service_record'
  TASK_ID_PARAM = 'task_id'
  RUN_ID_PARAM = 'run_id'
  HISTORY_LIMIT = 20

  def post(self):
    logging.debug('Handled: FoursquareFetchTask')

    # Read keys from the query.
    service_encoded = self.request.get(FoursquareFetchTask.SERVICE_PARAM)
    service_record_encoded = self.request.get(
        FoursquareFetchTask.SERVICE_RECORD_PARAM)
    task_id = self.request.get(FoursquareFetchTask.TASK_ID_PARAM)
    run_id = self.request.get(FoursquareFetchTask.TASK_ID_PARAM)
    if (service_encoded is None or service_record_encoded is None):
      self.response.clear()
      self.response.set_status(400, message='Missing required query parameter')
      return

    # Pull the objects from the datastore.
    service = Service.get(service_encoded)
    service_record = FoursquareServiceRecord.get(service_record_encoded)
    if (service is None or service_record is None):
      self.response.clear()
      self.response.set_status(400, message='Unknown service or record')
      return

    sinceid = service_record.sinceid
    logging.debug('Requesting history starting from: %s' % sinceid)

    foursquare_client = foursquareClient(service)
    response = foursquare_client.history(sinceid=sinceid,
        limit=FoursquareFetchTask.HISTORY_LIMIT)
    content = response.content
    checkins = json.loads(content)['checkins']

    def txn():
      for checkin in checkins:
        logging.debug(checkin)
        checkin_id = str(checkin['id'])
        key_name = 'checkin/%s' % checkin_id
        activity = FoursquareActivity(key_name=key_name, parent=service,
            checkin_id=checkin_id,
            checkin_json=json.dumps(checkin))
        activity.put()
        service_record.sinceid = checkin_id
      service_record.put()
    db.run_in_transaction(txn)

    if len(checkins):
      logging.debug('Fetched %s records. Queueing.' % len(checkins))
      FoursquareFetch.add_task(service, service_record, run_id, task_id)
    else:
      logging.debug('No records. Deactivating.')
      service_record.active = False
      service_record.put()


class FoursquareFetch(webapp.RequestHandler):
  """Fetch the user's foursquare history stream."""

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: FoursquareFetch')

    foursquare_service = user.findService(session, 'foursquare')
    service_record = FoursquareServiceRecord.lock(foursquare_service)
    run_id = int(time.time())
    FoursquareFetch.add_task(foursquare_service, service_record, run_id, 0)

  @classmethod
  def add_task(cls, service, service_record, run_id, task_id):
    # Describe the work
    service_key = str(service.key())
    service_record_key = str(service_record.key())
    task_id = int(task_id) + 1
    parameters = {
       FoursquareFetchTask.SERVICE_PARAM: service_key,
       FoursquareFetchTask.SERVICE_RECORD_PARAM: service_record_key,
       FoursquareFetchTask.TASK_ID_PARAM: task_id,
    }

    # Add it to the queue
    name = '%s-%s-%s' % (service_record_key, run_id, task_id)
    logging.debug('Adding to the taskqueue: %s' % name)
    taskqueue.add(url=FOURSQUARE_FETCH_TASK_PATH, params=parameters, name=name)


class FoursquareMatchVenueTask(webapp.RequestHandler):
  """Match a Venue in an Activity to a Place."""

  VENUE_PARAM = 'vid'

  def post(self):
    logging.debug('Handled: FoursquareMatchVenueTask')

    # Read keys from the query.
    venue_encoded = self.request.get(FoursquareMatchVenueTask.VENUE_PARAM)

    if venue_encoded is None:
      self.response.clear()
      self.response.set_status(400, message='Missing required query parameter')
      return

    # Pull the objects from the datastore.
    venue_entity = Venue.get(venue_encoded)
    if venue_entity is None:
      self.response.clear()
      self.response.set_status(400, message='Unknown venue')
      return
    venue = json.loads(venue_entity.json)

    # Store the place on the venue for futher processing.
    match = VenueMatcher.match(venue)
    if match.place is not None:
      venue_entity.set_place(json.dumps(match.place))
      venue_entity.put()


class FoursquareMatchVenue(webapp.RequestHandler):
  """Match all a user's Foursquare activity Venues to Places."""

  @login_required
  def get(self, user=None, session=None):
    logging.debug('Handled: FoursquareMatchVenue')

    query = Venue.all(keys_only=True).filter('place_exists =', False)

    for key in query:
      FoursquareMatchVenue.add_task(key)

  @classmethod
  def add_task(cls, venue_key):
    # Describe the work
    parameters = {
       FoursquareMatchVenueTask.VENUE_PARAM: venue_key,
    }

    # Add it to the queue
    taskqueue.add(url=FOURSQUARE_MATCH_VENUE_TASK_PATH, params=parameters)


class FoursquareVenueCacheTask(webapp.RequestHandler):

  def post(self):
    logging.debug('Handled: FoursquareVenueCacheTask')
    Venue.put_json(self.request.body)

  @classmethod
  def add(cls, venues):
    # Convert a python object to json, if necessary.
    if isinstance(venues, dict):
      venues = json.dumps(venues)
    # Cache the venues
    taskqueue.add(url=FOURSQUARE_VENUE_CACHE_TASK_PATH, payload=venues)


def create_application():
  """Create the application that will be run in main."""
  application = webapp.WSGIApplication(
      [
          # OAUTH HANDLERS
          (BUZZ_OAUTH_START_PATH, BuzzOAuthStartHandler),
          (BUZZ_OAUTH_CALLBACK_PATH, BuzzOAuthCallbackHandler),
          (FOURSQUARE_OAUTH_START_PATH, FoursquareOAuthStartHandler),
          (FOURSQUARE_OAUTH_CALLBACK_PATH, FoursquareOAuthCallbackHandler),
          (LATITUDE_OAUTH_START_PATH, LatitudeOAuthStartHandler),
          (LATITUDE_OAUTH_CALLBACK_PATH, LatitudeOAuthCallbackHandler),

          # AUTHENTICATED HANDLERS
          (HOME_PATH, HomeHandler),
          (START_PATH, StartHandler),
          (NEARBY_PATH, NearbyHandler),
          (NEARBYJS_PATH, NearbyJsHandler),
          (MATCH_PATH, MatchHandler),

          # AUTHENTICATED RPC HANDLERS
          #(BUZZ_PATH, BuzzRpcHandler),
          #(FOURSQUARE_PATH, FoursquareRpcHandler),
          #(LATITUDE_PATH, LatitudeRpcHandler),
          #(PLACES_PATH, PlacesRpcHandler),

          # TASK RUNNERS
          (FOURSQUARE_FETCH_PATH, FoursquareFetch),
          (FOURSQUARE_MATCH_VENUE_PATH, FoursquareMatchVenue),

          # TASKS
          (BUZZ_POST_TASK_PATH, BuzzPostTask),
          (FOURSQUARE_FETCH_TASK_PATH, FoursquareFetchTask),
          (FOURSQUARE_MATCH_VENUE_TASK_PATH, FoursquareMatchVenueTask),
          (FOURSQUARE_VENUE_CACHE_TASK_PATH, FoursquareVenueCacheTask),
      ],
      debug=DEBUG)
  return application


# -- Main entry point (two methods for profiling). -- #


def profile_main():
  """From http://code.google.com/appengine/kb/commontasks.html"""
  logging.debug('DEBUG Main Being Used')
  # This is the main function for profiling
  # We've renamed our original main() to real_main()
  import cProfile, pstats
  prof = cProfile.Profile()
  prof = prof.runctx("real_main()", globals(), locals())
  print "<div class=\"debug\"><pre>"
  stats = pstats.Stats(prof)
  stats.sort_stats("time")  # Or cumulative
  stats.print_stats(80)  # 80 = how many to print
  # The rest is optional.
  # stats.print_callees()
  # stats.print_callers()
  print "</pre></div>"


def real_main():
  """Hide the real main method so that we can run profiling."""
  logging.debug('Real Main Being Used')
  handlers.CGIHandler().run(create_application())


def set_main():
  """Set __module__.main to either the real or debugging main.

  Uses global "DEBUG"
  """
  global main
  if DEBUG:
    main = profile_main
  else:
    main = real_main


# this needs to be executed at the module level or main() will not be cached by
# GAE.
set_main()


if __name__ == '__main__':
  main()