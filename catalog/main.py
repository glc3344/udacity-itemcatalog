from flask import Flask, render_template, redirect, request, url_for, flash, \
    jsonify, make_response
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

from flask import session as login_session
import random, string

from authomatic.adapters import WerkzeugAdapter
from authomatic import Authomatic

from config import CONFIG

app = Flask(__name__)

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Instantiate Authomatic.
authomatic = Authomatic(CONFIG, 'your secret string', report_errors=False)


@app.route('/')
@app.route('/index')
def show_all():
    user = session.query(User).one()
    return render_template('index.html', user=user)


@app.route('/login/<provider_name>/', methods=['GET', 'POST'])
def login(provider_name):
    response = make_response()
    result = authomatic.login(WerkzeugAdapter(request, response), provider_name)
    if result:
        if result.user:
            result.user.update()
        return render_template('login.html', result=result)
    return response




#####################
#  GOOGLE Sign In   #
#####################












if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
