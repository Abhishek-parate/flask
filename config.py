import os



class Config:
    
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'mail.techinbox.in'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'ceo@techinbox.in'
    MAIL_PASSWORD = 'Abhi@9860'
    MAIL_DEFAULT_SENDER= 'ceo@techinbox.in'
