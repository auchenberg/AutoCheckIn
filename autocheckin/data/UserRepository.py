import datamodel
from google.appengine.ext import db
from google.appengine.api import users

def getAllActive():
    return datamodel.User.all().filter('isPaused = ', False)

def getByKey(userKey):
    user =  datamodel.User.get(userKey)
    return user

def get(user):
    query = db.Query(datamodel.User)
    query.filter('details =', user)
    results = query.fetch(1)
    if len(results) == 0:
        return None
    else:
        return results[0]

def new(user):
    userProfile = datamodel.User()
    userProfile.details = user
    userProfile.isPaused = False
    userProfile.put()
    
    return userProfile
 
def pauseUser(userKey):
    user =  datamodel.User.get(userKey)
    user.isPaused = True
    user.put()
    return user
    
def startUser(userKey):
    user =  datamodel.User.get(userKey)
    user.isPaused = False
    user.put()
    return user
