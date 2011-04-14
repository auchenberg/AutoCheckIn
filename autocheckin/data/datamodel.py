from google.appengine.ext import db
from google.appengine.api import users

class User(db.Model):
    details = db.UserProperty(required=False)
    fullname = db.StringProperty(required=False) 
    isPaused = db.BooleanProperty()
          
class Service(db.Model): 
    name = db.StringProperty(required=True)
    access_token = db.StringProperty(required=True)
    access_secret = db.StringProperty(required=True)
    user = db.ReferenceProperty(User, collection_name='services')
    
class Location(db.Model): 
    latitude = db.FloatProperty(required=True)
    longitude = db.FloatProperty(required=True)
    accuracy = db.IntegerProperty()
    source = db.ReferenceProperty(Service)
    user = db.ReferenceProperty(User, collection_name='location')
    importDate = db.DateTimeProperty(auto_now_add=True)
    
class UserSetting(db.Model): 
    name = db.StringProperty(required=True)
    value = db.StringProperty(required=True)
    user = db.ReferenceProperty(User, collection_name='settings')