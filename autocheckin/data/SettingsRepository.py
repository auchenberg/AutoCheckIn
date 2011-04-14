import datamodel
from google.appengine.ext import db
from google.appengine.api import users

def getByKey(key):
    user =  datamodel.UserSetting.get(key)
    return user

def get(user, name):
    query = db.Query(datamodel.UserSetting)
    query.filter('user =', user)
    query.filter('name =', name)
    results = query.fetch(1)
    if len(results) == 0:
        return None
    else:
        return results[0]

def getValue(user, name):
    query = db.Query(datamodel.UserSetting)
    query.filter('user =', user)
    query.filter('name =', name)
    results = query.fetch(1)
    if len(results) == 0:
        return None
    else:
        return results[0].value
                
                        
def createOrSet(user, name, value):
    query = db.Query(datamodel.UserSetting)
    query.filter('user =', user)
    query.filter('name =', name)
    results = query.fetch(1)
    if len(results) == 0:
        setting = datamodel.UserSetting(user = user, name = name, value = value)
        setting.put()
        return setting
    else:
        setting = results[0]
        setting.value = value
        setting.put();
        return setting
