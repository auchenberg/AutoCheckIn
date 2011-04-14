import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lib'))
from google.appengine.ext import webapp
from google.appengine.api.labs import taskqueue
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.api import users
import logging
import datetime
import oauth2 as oauth

from operator import itemgetter, attrgetter
from autocheckin import settings, oauth_helper
from autocheckin.clients import foursquare, latitude
from autocheckin.data import UserRepository, LocationRepository, ServiceRepository, SettingsRepository
from geopy import distance as geopy_distance 

def geocode_distance((x1, y1), (x2, y2), unit='km'): 
   if (x1, y1) == (x2, y2): 
       return 0 
   d = geopy_distance.distance((x1, y1), (x2, y2)) 
   return d.kilometers * 1000    
       
class LocationServiceHandler(webapp.RequestHandler):   
    def get(self):
        self.response.out.write('sdfsd')
    def post(self):
        # extract the parameters for this task   
        userKey = self.request.get('userKey')

        logging.info('started handling location-task with user-key: %s' % userKey)

        # 1. get User
        userProfile = UserRepository.getByKey(userKey)
        if(userProfile == None):
            logging.warning('Skipping. Didnt find the user (user-key: %s)' % userKey)
            return ""
            
        logging.info('User Found for with user-key: %s' % userKey)
        # 2. get current location
        currentLocation = LocationRepository.getLatestForUser(userProfile)
        latitudeService = ServiceRepository.get('latitude', userProfile)
        
        if(latitudeService == None):
            logging.warning('Skipping. User didnt have a latitude-service installed (user-key: %s)' % userKey)  
            return ""
            
        # 3. get Location from Latitude
        client = latitude.LatitudeClient(latitudeService.access_token, latitudeService.access_secret)
        latitudeLocation = client.current_location()

        # Check if authorized
        if(latitudeLocation and 'error' in latitudeLocation and latitudeLocation['error']['message'] == 'Unknown authorization header'):
            logging.warning('Skipping, unauthorized from latitude (userkey: %s)' % userKey)
            logging.warning('Removing service, since its unauthorized (userkey: %s, serviceKey: %s)', userKey, latitudeService.key())
            ServiceRepository.delete(latitudeService.key())
            return ""
            
        if not latitudeLocation or not 'data' in latitudeLocation:
             logging.warning('Aborting, couldnt get location form Google Latitude (userkey: %s, location: %s)', userKey, latitudeLocation)   
             return ""
             
        logging.info('Location received Google Latitude (userkey: %s, location: %s) ', userKey, latitudeLocation)  
        location = latitudeLocation['data']       

        if not location or not 'latitude' in location:
            logging.warning('Aborting, Google Latitude did not return a valid location (userkey: %s, location: %s)', userKey, location)
            return ""
            
        #userLocationAccuracyThreshold = SettingsRepository.getValue(userProfile, 'location-accuracy-threshold')
        #if(userLocationAccuracyThreshold == None):
        #    userLocationAccuracyThreshold = 100
        #else:
        #    userLocationAccuracyThreshold = int(userLocationAccuracyThreshold)
        userLocationAccuracyThreshold = 80
                    
        if(location['accuracy'] > userLocationAccuracyThreshold):
            logging.warning('Skipping, Accuracy for location isnt good enough (more than %s meters) (userkey: %s, location: %s)', userLocationAccuracyThreshold, userKey, location)
            return ""     
             
        # 4. Has the location changed?
        if(currentLocation != None and currentLocation.latitude == location['latitude'] and currentLocation.longitude == location['longitude']):            
            timeDelta = datetime.datetime.utcnow() - currentLocation.importDate
            
            userLocationTimeThreshold = SettingsRepository.getValue(userProfile, 'location-time-threshold')
            if(userLocationTimeThreshold == None):
                userLocationTimeThreshold = 10
            else:
                userLocationTimeThreshold = int(userLocationTimeThreshold)
                                
            if timeDelta < datetime.timedelta(minutes=userLocationTimeThreshold):
                logging.warning('Skipping, Location changed, but user hasn been there for %s minutes (userkey: %s)', userLocationTimeThreshold, userKey) 
                return ""
            
            userLocationDistanceThreshold = SettingsRepository.getValue(userProfile, 'location-distance-threshold')
            if(userLocationDistanceThreshold == None):
                userLocationDistanceThreshold = 10      
            else:
                userLocationDistanceThreshold = int(userLocationDistanceThreshold)     
                                      
            #distance = geocode_distance( (currentLocation.latitude, currentLocation.longitude), (location['latitude'], location['longitude']) )
            
            #if( (distance) < userLocationDistanceThreshold):
            #    logging.warning('Skipping, Location changed %s meters, but not more than the location treshhold (%s meters) (userkey: %s)', distance, userLocationDistanceThreshold, userKey) 
            #    return ""
                 
            logging.info('Continue, user hasn been there for time limit (userkey: %s)' % userKey) 
            # 5. Add Foursquare task
            logging.info('Adding task "/task/checkin" to checkin-queue. (userkey: %s, locationKey: %s)', userKey, currentLocation.key())
            task = taskqueue.Task(url='/task/checkin', params={ 'userKey': userKey, 'locationKey' : currentLocation.key() })   
            task.add('checkin')  
        elif currentLocation == None:
            # 5. Store new Location  
            logging.info('Storing location for the first time (userkey: %s, location: %s) ', userKey, location)
            LocationRepository.new(location['latitude'], location['longitude'], location['accuracy'], latitudeService, userProfile)            
        else:    
            # 5. Store new Location  
            logging.info('Storing new location (userkey: %s, location: %s) ', userKey, location)
            LocationRepository.new(location['latitude'], location['longitude'], location['accuracy'], latitudeService, userProfile)
 
        return ""
        
def main():
    run_wsgi_app(webapp.WSGIApplication([
        ('/task/location', LocationServiceHandler)
    ]))

if __name__ == '__main__': 
    main()
                  