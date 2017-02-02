import httplib2
import requests
from flask import Flask, render_template, redirect, request, url_for, flash, \
    jsonify, make_response
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
import json, random, string

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Item Catalog"

#### Connect to Database and create session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)

DBSession = sessionmaker(bind=engine)
session = DBSession()


#### Handlers

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """Redirects the user to the Google login page."""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Index page showing all categories and recently added items
@app.route('/')
@app.route('/index')
def show_all():
    """Lists the items which were recently created in descending order."""
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by((desc(Item.id)))
    if 'username' not in login_session:
        return render_template('index.html')
    else:
        return render_template('index.html',
                               user_name=login_session['username'],
                               picture=login_session['picture'],
                               categories=categories,
                               items=items)


# Displays individual category page with category specific items
@app.route('/category/<category_name>/items')
def category_index(category_name):
    """Lists all items of the specified category."""
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category=category).all()
    return render_template('category_index.html', category=category,
                           items=items, user_name=login_session[
            'username'], picture=login_session['picture'])


# Allows logged in user to create new category
@app.route('/category/new', methods=['GET', 'POST'])
def new_category():
    """Create a new category."""
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        new_category = Category(
            name=request.form['category_name'], user_id=login_session[
                'user_id'])
        session.add(new_category)
        flash('Category \"%s\" was successfully created!' % new_category.name)
        session.commit()
        return redirect(url_for('show_all'))
    else:
        return render_template('newCategory.html', user_name=login_session[
            'username'], picture=login_session['picture'])


# Allows category owner to edit category name
@app.route('/category/<category_name>/edit/', methods=['GET', 'POST'])
def edit_category(category_name):
    """Edit category with specified name."""
    editedCategory = session.query(
        Category).filter_by(name=category_name).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedCategory.user_id != login_session['user_id']:
        flash(
            "You are not authorized to edit this category. Please create your own category in order to edit")
        return redirect(url_for('show_all'))
    if request.method == 'POST':
        if request.form['category_name']:
            editedCategory.name = request.form['category_name']
        session.add(editedCategory)
        session.commit()
        flash('Category successfully edited to \"%s\"' % editedCategory.name)
        return redirect(url_for('show_all'))
    else:
        return render_template('editCategory.html', category=editedCategory,
                               user_name=login_session[
                                   'username'],
                               picture=login_session['picture'])


# Allows category owner to delete category along with all of its current items
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def delete_category(category_id):
    """Edit category with specified ID."""
    delete_items = session.query(Item).filter_by(category_id=category_id).all()
    delete_category = session.query(
        Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if delete_category.user_id != login_session['user_id']:
        flash(
            "You are not authorized to delete this category. Please create "
            "your own category in order to edit/delete!")
        return redirect(url_for('show_all'))
    if request.method == 'POST':
        for i in delete_items:
            session.delete(i)
        session.delete(delete_category)
        session.commit()
        flash('Category \"%s\" was successfully deleted!' %
              delete_category.name)
        return redirect(url_for('show_all'))
    else:
        return render_template('deleteCategory.html',
                               category=delete_category,
                               user_name=login_session[
                                   'username'],
                               picture=login_session['picture'])


# Allows a logged in user to add a new item to specific category
@app.route('/category/<int:category_id>/item/new', methods=['GET', 'POST'])
def new_item(category_id):
    """Creates a new item."""
    if 'username' not in login_session:
        flash("You must be logged in to add an item to a category!")
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        new_item = Item(name=request.form['item_name'],
                        description=request.form[
                            'description'], category_id=category_id,
                        user_id=login_session[
                            'user_id'])
        session.add(new_item)
        session.commit()
        flash('Item \"%s\" was successfully created!' % new_item.name)
        return redirect(url_for('show_all'))
    else:
        return render_template('newItem.html', cat_name=category.name,
                               category_id=category_id,
                               user_name=login_session[
                                   'username'],
                               picture=login_session['picture'])


# Displays detailed information about the specific item
@app.route('/category/<category_name>/<item_name>')
def item_description(category_name, item_name):
    """Shows the details of the specified item."""
    item = session.query(Item).filter_by(name=item_name).one()
    category = session.query(Category).filter_by(name=category_name).one()
    return render_template('itemDescription.html', item=item,
                           category=category, user_name=login_session[
            'username'],
                           picture=login_session['picture'])


# Allows item creator to edit items properties
@app.route('/category/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
def edit_item(category_name, item_name):
    """Edit the item with the given name."""
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(name=item_name).one()
    if login_session['user_id'] != editedItem.user_id:
        flash("You are not authorized to edit \"%s\"" % editedItem.name)
        return redirect(url_for('show_all'))
    if request.method == 'POST':
        if request.form['item_name']:
            editedItem.name = request.form['item_name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash("\"%s\" Successfully Edited" % editedItem.name)
        return redirect(url_for('category_index', category_name=
        category_name))
    else:
        return render_template('editItem.html', category_name=category_name,
                               item=editedItem, user_name=login_session[
                'username'],
                               picture=login_session['picture'])


# Allows item creator to delete their item from the DB
@app.route('/category/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
def delete_item(category_name, item_name):
    """Delete the item with the given name."""
    if 'username' not in login_session:
        return redirect('/login')
    deleteItem = session.query(Item).filter_by(name=item_name).one()
    if login_session['user_id'] != deleteItem.user_id:
        flash("You are not authorized to delete \"%s\"" % deleteItem.name)
        return redirect(url_for('show_all'))
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        flash("\"%s\" Successfully Deleted!" % deleteItem.name)
        return redirect(url_for('category_index', category_name=
        category_name))
    else:
        return render_template('deleteItem.html', item_name=deleteItem,
                               category_name=category_name,
                               user_name=login_session[
                                   'username'],
                               picture=login_session['picture'])


#####################
#  JSON Endpoint    #
#####################

@app.route('/category/<category_name>/JSON')
def categoryJSON(category_name):
    """Returns the catalog in JSON notation."""
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category=category).all()
    return jsonify(Items=[i.serialize for i in items])


#####################
#  GOOGLE Sign In   #
#####################

@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Login authentication with Google"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Welcome %s!" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/logout')
def logout():
    if 'username' not in login_session:
        flash("You must be signed in to logout")
        return redirect('/login')
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
          login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("You have successfully been logged out.")
        return render_template('index.html')
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


#### User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
