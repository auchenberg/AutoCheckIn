from flask import Module, g, redirect, render_template, request, url_for
from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.api import users
import simplejson as json
from autocheckin import data, clients, settings, oauth_helper
import logging
import datetime
main = Module(__name__)

@main.route('/')
def index():

    return render_template('welcome.html');
