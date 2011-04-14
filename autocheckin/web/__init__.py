import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../lib'))

from flask import Module, Flask, g, redirect, render_template, request, session, url_for
from autocheckin.web.main import main
from autocheckin.web.database import database

application = Flask(__name__)
application.register_module(database)
application.register_module(main)

if __name__ == '__main__':
    application.run(debug=True)