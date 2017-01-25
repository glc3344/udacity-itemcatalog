from flask import Flask, render_template, redirect, request, url_for, flash, \
    jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item


app = Flask(__name__)

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/')
@app.route('/index')
def show_all():
    return "This is the main page!"
















if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)