import datamodel
from google.appengine.ext import db
from google.appengine.api import users

def getAll(user):
    return datamodel.User.all().filter('user =', user)
    
def get(name, user):
    query = db.Query(datamodel.Service)
    query.filter('user =', user)
    query.filter("name =", name)
    results = query.fetch(1)
    if len(results) == 0:
        return None
    else:
        return results[0]
        
def delete(key):
    service =  datamodel.Service.get(key)
    service.delete();

def new(user, name, access_key, access_secret):
    service = datamodel.Service(user = user, name = name, access_token = access_key, access_secret = access_secret)
    service.put()
    
    return service
