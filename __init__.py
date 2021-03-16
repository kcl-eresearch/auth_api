from flask import Flask
from lib.aapi import aapi

app = Flask(__name__)

@app.route('/')
def route_root():
    aapi = aapi()
    aapi.flask_response({'status': 'OK'})
