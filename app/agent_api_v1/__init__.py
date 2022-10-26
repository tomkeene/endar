from flask import Blueprint
api = Blueprint('agent_api', __name__)

from . import views
