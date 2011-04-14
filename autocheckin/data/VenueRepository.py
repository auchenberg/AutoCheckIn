import logging
from google.appengine.ext import db
from google.appengine.api import users
from operator import itemgetter, attrgetter
from autocheckin import settings, oauth_helper
from autocheckin.clients import foursquare, latitude
from autocheckin.data import UserRepository, LocationRepository, ServiceRepository, SettingsRepository

def getNearByVenues(user, location):

    foursquareService = ServiceRepository.get('foursquare', user)

    logging.info('Trying to fecth data from FourSquare (user-key%s)' % user.key)    
    client = foursquare.FoursquareClient(foursquareService.access_token, foursquareService.access_secret)
    
    # Get nearby Venues        
    venues = client.venues(location.latitude, location.longitude)
    venueList = []

    if venues and not 'groups' in venues:
        logging.warning('Skipping, couldnt get near by venues for user (userkey: %s)' % userKey)
        return None
        
    # Merge all Venues
    for group in venues['groups']:
        venueList.extend(group['venues'])
    
    if(len(venueList) == 0):
        logging.warning('Skipping, No near by venues found for user (userkey: %s)' % userKey)
        return None
        
    # Get venue stats
    for venue in venueList:  
        #venue['stats'] = client.venue(venue['id'])['venue']['stats']
        venue['rank'] = 1
        venue['score'] = 0
        
    # Category filter
    
    # Ranking
    for venue in venueList:  
         # if venue['stats']['beenhere']['me'] == True:
         #    venue['rank'] += 2
        
        venue['score'] = int(venue['rank'])  * (int(location.accuracy) - int(venue['distance']))
    
    # 7. Sorting
    def distance_compare(x, y):
        return y['score'] - x['score']

    sortedVenues = sorted(venueList, cmp = distance_compare)
             
    return sortedVenues
    
    