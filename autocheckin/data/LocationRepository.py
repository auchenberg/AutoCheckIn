import datamodel
from google.appengine.ext import db
from google.appengine.api import users

def getLatestForUser(user):
    query = db.Query(datamodel.Location)
    query.filter('user =', user)
    query.order('-importDate')
    results = query.fetch(1)
    if len(results) == 0:
        return None
    else:
        return results[0]
def getByKey(key):
    location =  datamodel.Location.get(key)
    return location   
    
def new(latitude, longitude, accuracy, source, user):
    location = datamodel.Location(latitude = latitude, longitude = longitude, accuracy = accuracy, source = source, user = user)
    location.put()

    return location
