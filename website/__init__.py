from flask import Flask
from os import path

def create_app():
    app=Flask(__name__)

    app.config['Secret_key'] = "Helloandwelcometostegandcrypt"

    from .views import views

    app.register_blueprint(views, url_prefix="/")

    return app


    
