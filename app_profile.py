#!/usr/bin/python
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

from wsgiref.handlers import CGIHandler
from autocheckin.web.profile import application

CGIHandler().run(application)
