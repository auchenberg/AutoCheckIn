import logging
import urllib
import time
import random
import urlparse
import hmac
import binascii
import httplib2
import oauth2 as oauth
import settings

try:
    from urlparse import parse_qs, parse_qsl
except ImportError:
    from cgi import parse_qs, parse_qsl


class OAuthHelper(object):
      consumer = None
      client = None
  
      def __init__(self, oauth_consumer):
          self.consumer = oauth_consumer
          self.client = oauth.Client(oauth_consumer)
      
      def get_request_token(self, request_token_url, callback_url):
          resp, content = self.client.request(request_token_url, 'POST', headers=settings.HEADERS, body=urllib.urlencode({ 'oauth_callback': callback_url }, True))
          if resp['status'] != '200': raise Exception('Invalid response %s.' % content)

          return oauth.Token.from_string(content)

      def get_authorize_url(self, request_token, authorize_url):

          base_url = urlparse.urlparse(authorize_url)
          query = parse_qs(base_url.query)
          query['oauth_token'] = request_token.key

          url = (base_url.scheme, base_url.netloc, base_url.path, base_url.params,urllib.urlencode(query, True), base_url.fragment)

          authorize_url = urlparse.urlunparse(url)

          return authorize_url

      def get_access_token(self, request_token, verifier, access_token_url):
          request_token.set_verifier(verifier)
        
          client = oauth.Client(self.consumer, request_token)

          resp, content = client.request(access_token_url, 'POST', headers=settings.HEADERS, body = None)
          if resp['status'] != '200': raise Exception('Invalid response %s.' % content)

          return oauth.Token.from_string(content)
     
          