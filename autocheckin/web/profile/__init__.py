import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../lib'))

from jinja2 import Environment, FileSystemLoader
from flask import Module, Flask, g, redirect, render_template, request, session, url_for
from autocheckin.web.profile.profile import profile
from autocheckin.web.profile.checkin import checkin
from autocheckin.web.profile.auth import auth

application = Flask(__name__)
application.register_module(checkin)
application.register_module(auth)
application.register_module(profile)


if __name__ == '__main__':
    application.run(debug=True)