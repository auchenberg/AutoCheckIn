from google.appengine.ext import webapp
from google.appengine.api.labs import taskqueue
from google.appengine.ext import db

from autocheckin.data import UserRepository, LocationRepository, ServiceRepository, SettingsRepository

import logging

class ServiceHandler(webapp.RequestHandler):   
    users = UserRepository.getAllActive()
    for user in users: 
        task = taskqueue.Task(url='/task/location', params={ 'userKey': user.key() }) 
        task.add('location') 
        logging.info('added task to location-queue with user-key: %s' % user.key())
