import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lib'))
from google.appengine.ext import webapp
from google.appengine.api.labs import taskqueue
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.api import users
import logging
import oauth2 as oauth

from operator import itemgetter, attrgetter
from autocheckin import settings, oauth_helper
from autocheckin.clients import foursquare, latitude
from autocheckin.data import UserRepository, LocationRepository, ServiceRepository, SettingsRepository, VenueRepository


import logging

class CheckinService(webapp.RequestHandler):   
     
    def post(self):
        # extract the parameters for this task   
        userKey = self.request.get('userKey')
        locationKey = self.request.get('locationKey')
        
        if(userKey == None):
            logging.error('Aborting, didnt receive a userKey')
            return ""
        if(locationKey == None):
            logging.error('Aborting, didnt receive a locationKey')
            return ""
                
        logging.info('started handling checkin-task with user-key: %s' % userKey)

        # 1. get User
        userProfile = UserRepository.getByKey(userKey)
        if(userProfile == None):
            logging.error('Aborting. Didnt find the user (user-key: %s)' % userKey)
            return ""
        
        # 2. get Location
        location = LocationRepository.getByKey(locationKey)
        if(location == None):
            logging.error('Aborting. Didnt find location for user (user-key: %s, location : %s)', userKey, location)
            return ""
        
        # 3. foursquare client    
        foursquareService = ServiceRepository.get('foursquare', userProfile)
        if(foursquareService == None):
            logging.warning('Skipping. User didnt have a foursquare-service installed (user-key: %s)' % userKey) 
            return ""

        logging.info('Trying to fecth data from FourSquare (user-key%s)' % userKey)    
        client = foursquare.FoursquareClient(foursquareService.access_token, foursquareService.access_secret) 
        
        # 4. Get history
        logging.info('Trying to get history from FourSquare (user-key%s)' % userKey) 
        history = client.history(1)
        
        if(history and 'unauthorized' in history):
            logging.warning('Skipping, unauthorized from foursquare (userkey: %s)' % userKey)
            logging.warning('Removing service, since its unauthorized (userkey: %s, serviceKey: %s)', userKey, foursquareService.key())
            ServiceRepository.delete(foursquareService.key())
            return ""
            
            
        if history and not 'checkins' in history:
            logging.warning('Skipping, couldnt get history for user (userkey: %s)' % userKey)
            lastVenueId = 0
        else:
            logging.info('Got history for user (userkey: %s, history: %s)', userKey, history)
            lastVenueId = history['checkins'][0]['venue']['id']
            
        logging.info('Foursquare lastVenueId: %s' % lastVenueId)

        # 5. Get Near by venues        
        venues = VenueRepository.getNearByVenues(userProfile, location)
        
        if(venues == None):
            return ""
            
        theVenue = venues[0]    
        
        if(lastVenueId == theVenue['id']):
            logging.warning('Skipping, User already checked into this venue (userkey: %s, venueId: %s)', userKey, theVenue['id'])
            return ""
          
        # 8. Check in
        logging.info('Foursquare checking user into new venue (id= %s)' % theVenue['id']) 
        client.checkin(theVenue['id'], None, '(autocheckin.appspot.com)', location.latitude, location.longitude)
            
        return ""
        
def main():
    run_wsgi_app(webapp.WSGIApplication([
        ('/task/checkin', CheckinService)
    ]))

if __name__ == '__main__': 
    main()        