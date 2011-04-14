from autocheckin import settings
from google.appengine.api import urlfetch
import simplejson as json
import oauth2 as oauth
import urllib
import logging
import httplib2

class LatitudeClient(object):
    
    def __init__(self, token, secret):
        self._token = token
        self._secret = secret
    
    def _invoke(self, path, method='GET', params=None):
        resource_url = "https://www.googleapis.com/latitude/v1/%s" % (path.lstrip('/'))
    
        token = oauth.Token(self._token, self._secret)
        consumer = oauth.Consumer(settings.latitude_key, settings.latitude_secret)
        oauth_request = oauth.Request.from_consumer_and_token(consumer, token, method, resource_url, params)
        oauth_request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, token)

        headers = {}
        headers.update(oauth_request.to_header(realm = 'http://*.kenneth.io'))
        headers['user-agent'] = 'jcgregorio-test-client'
        headers['content-type'] = 'application/json; charset=UTF-8'
        
        if params:
            resource_url = "%s?%s" % (resource_url, urllib.urlencode(params))
            
        response = urlfetch.fetch(url = resource_url, method = urlfetch.GET, headers = headers)
        
        return json.loads(response.content)
    
    def current_location(self):    
        return self._invoke("/currentLocation", 'GET', {'granularity': 'best'})

    def update_location(self, lat, lng, accuracy): 
        resource_url = "https://www.googleapis.com/latitude/v1/currentLocation"
        parameters = {"data":{"latitude" : lat, "longitude": lng, "accuracy": accuracy}}
     
        header = {}
        header['Content-Type'] = 'application/json'
        
        token = oauth.Token(self._token, self._secret)
        consumer = oauth.Consumer(settings.latitude_key, settings.latitude_secret)        
        client = oauth.Client(consumer, token)

        resp, content = client.request(resource_url, 'POST', headers = header, body = json.dumps(parameters))
        return json.loads(content)
