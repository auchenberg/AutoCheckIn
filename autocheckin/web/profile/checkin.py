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

from autocheckin import settings, oauth_helper, clients
from autocheckin.data import UserRepository, LocationRepository, ServiceRepository, SettingsRepository, VenueRepository

checkin = Module(__name__)


@checkin.route('/checkin', methods=['GET'])
def checkin_dummy():
    userProfile = UserRepository.get(users.get_current_user())
    userKey = userProfile.key()

    currentLocation = LocationRepository.getLatestForUser(userProfile)
     
    # 5. Add Foursquare task
    task = taskqueue.Task(url='/task/checkin', params={ 'userKey': userKey, 'locationKey' : currentLocation.key() }) 
    task.add('checkin')
    
    return "Dummy check in task"
    
@checkin.route('/profile/foursquare')
def fs():
    userProfile = UserRepository.get(users.get_current_user()) 
    currentLocation = LocationRepository.getLatestForUser(userProfile)
    # 5. Get Near by venues            
    venues = VenueRepository.getNearByVenues(userProfile, currentLocation)

    return json.dumps(venues)

@checkin.route('/profile/latitude')
def blah():
    userProfile = UserRepository.get(users.get_current_user()) 

    service = ServiceRepository.get('latitude', userProfile)
    userProfile = UserRepository.get(users.get_current_user())

    client = clients.latitude.LatitudeClient(service.access_token, service.access_secret)
    location = client.current_location()

    return json.dumps(location)
    
@checkin.route('/profile/fake')
def fake():
    lng = request.args.get('lng')
    lat = request.args.get('lat')
    accuracy = request.args.get('a')
   
    logging.warning('Faking location: %s)' % accuracy) 
        
    userProfile = UserRepository.get(users.get_current_user()) 

    service = ServiceRepository.get('latitude', userProfile)
    userProfile = UserRepository.get(users.get_current_user())

    client = clients.latitude.LatitudeClient(service.access_token, service.access_secret)
    location = client.update_location(lat, lng, accuracy)
   
    return json.dumps(location)
    
@checkin.route('/profile/startit')
def start():
    key = request.args.get('key')

    user = UserRepository.getByKey(key)
    task = taskqueue.Task(url='/task/location', params={ 'userKey': user.key() }) 
    task.add('location')
       
    return "Added to queue"
            