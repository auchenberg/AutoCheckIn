__version__ = '0.1'

HEADERS = {
    'content-type': 'application/x-www-form-urlencoded'
}

latitude_key = 'autocheckin.appspot.com'
latitude_secret = 'MaDd35RT60WE8otdLsWDEsu0'

latitude_request_token_url = 'https://www.google.com/accounts/OAuthGetRequestToken?scope=https://www.googleapis.com/auth/latitude'
latitude_authorize_url = 'https://www.google.com/latitude/apps/OAuthAuthorizeToken?domain=autocheckin.appspot.com&granularity=best&location=all'
latitude_access_token_url = 'https://www.google.com/accounts/OAuthGetAccessToken'


foursquare_key = 'FR2XN3L4NX4OSBQDAGHF44MVBJYBW5FMAOKEMLSTRC03RBIR'
foursquare_secret = 'T25QTO2W25VNOROO5WOXAOI4BZDRTZGWA4QJ4CEWMCG2KJLD'

foursquare_request_token_url = 'http://foursquare.com/oauth/request_token'
foursquare_authorize_url = 'http://foursquare.com/oauth/authorize'
foursquare_access_token_url = 'http://foursquare.com/oauth/access_token'

isDebug = False
