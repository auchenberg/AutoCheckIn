from flask import Module, g, redirect, render_template, request, url_for
from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.api import users
import simplejson as json
from autocheckin import clients, settings, oauth_helper
from autocheckin.data import UserRepository, LocationRepository, ServiceRepository, SettingsRepository
import logging
import datetime

profile = Module(__name__)

@profile.route('/profile')
def profile_index():
    currentUser = users.get_current_user()
    
    userProfile = UserRepository.get(currentUser) 
    
    if userProfile == None:
        userProfile = UserRepository.new(currentUser)   
            
    logging.info('userprofile %s' % userProfile)
    
    if(userProfile.services):
        isLatitudeInstalled = ServiceRepository.get('latitude', userProfile) != None
        isFoursquareInstalled = ServiceRepository.get('foursquare', userProfile) != None
        
    if(isLatitudeInstalled == False and isFoursquareInstalled == False):
        return render_template('setup_step1.html', user=currentUser, logout_url=users.create_logout_url("/"));

    if(isLatitudeInstalled == False and isFoursquareInstalled == True):
            return render_template('setup_step1.html', user=currentUser, logout_url=users.create_logout_url("/"));

    if(isLatitudeInstalled == True and isFoursquareInstalled == False):
        return render_template('setup_step2.html', user=currentUser, logout_url=users.create_logout_url("/"));
    
    if(userProfile.isPaused == True):                
        return render_template('setup_off.html', user=currentUser, logout_url=users.create_logout_url("/"));
        
    return render_template('setup_on.html', user=currentUser, logout_url=users.create_logout_url("/"));

@profile.route('/profile/pause')
def profile_pause():
    userProfile = UserRepository.get(users.get_current_user()) 
    
    UserRepository.pauseUser(userProfile.key())
    return redirect(url_for('profile.profile_index'))

@profile.route('/profile/start')
def profile_start():
    userProfile = UserRepository.get(users.get_current_user()) 
    UserRepository.startUser(userProfile.key())
    return redirect(url_for('profile.profile_index'))

@profile.route('/profile/settings')
def profile_settings():
    settings = { 'timeSetting' : '5', 'distanceSetting' : 0, 'accuracySetting' : 100 }
    
    currentUser = users.get_current_user()
    userProfile = UserRepository.get(currentUser) 

    timeSetting = SettingsRepository.get(userProfile, 'location-time-threshold')
    distanceSetting = SettingsRepository.get(userProfile, 'location-distance-threshold')
    
    if(timeSetting != None):
        settings['timeSetting'] = timeSetting.value
    if(distanceSetting != None):
        settings['distanceSetting'] = distanceSetting.value

    return render_template('settings.html', user=currentUser, logout_url=users.create_logout_url("/"), settings = settings);

@profile.route('/profile/settings', methods=['POST'])
def profile_settings_save():
    currentUser = users.get_current_user()
    userProfile = UserRepository.get(currentUser) 

    SettingsRepository.createOrSet(userProfile, 'location-time-threshold', request.form['location-time-threshold'] )
    SettingsRepository.createOrSet(userProfile, 'location-distance-threshold', request.form['location-distance-threshold'])

    return redirect(url_for('profile.profile_settings'))
     
@profile.route('/profile/test')
def profile_test():
    currentUser = users.get_current_user()
    userProfile = UserRepository.get(users.get_current_user()) 
    logging.error('userProfile %s' % userProfile.services.fetch(1))
    
    currentLocation = LocationRepository.getLatestForUser(userProfile)
    timeDelta = datetime.datetime.utcnow() - currentLocation.importDate
    
    logging.info('Skipping, Location changed, but user hasn been there for time limit (timeDelta: %s)' % timeDelta) 
    
    if timeDelta < datetime.timedelta(minutes=5):
         logging.info('6min (userkey: %s)' % timeDelta) 
         return ""
         
    return 'none'


