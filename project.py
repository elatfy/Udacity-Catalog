from flask import Flask, render_template, request, abort
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('g_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog"

# DB Handler

engine = create_engine('sqlite:///catalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

# CSRF


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = login_session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            abort(403)


def generate_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = some_random_string()
    return login_session['_csrf_token']


def some_random_string():
    return ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for x in xrange(32))
app.jinja_env.globals['csrf_token'] = generate_csrf_token


# User Handler

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


@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(desc(Item.created_date))
    return render_template('home.html', categories=categories, items=items)

# Show Category


@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/items/')
def showCategory(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category.id).order_by(desc(Item.created_date)).all()
    return render_template('items.html', category=category, items=items)

# New Category form


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        flash("Please Login to be able to add new category")
        return redirect('/login')
    if request.method == 'POST':
        if request.form['name']:
            newCategory = Category(
                name=request.form['name'], user_id=login_session['user_id'])
            session.add(newCategory)
            flash('New Category %s Successfully Created' % newCategory.name)
            session.commit()
            return redirect(url_for('showCatalog'))
        else:
            error = "One or more Invalid Values"
            return render_template('new-category.html', error=error)
    else:

        return render_template('new-category.html')


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):

    if 'username' not in login_session:
        flash("Please Login to be able to add edit category")
        return redirect('/login')
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        flash("""You are not authorized to edit this category.
            Please create your own category in order to edit.""")
        return redirect(url_for('showCategory', category_id=category_id))
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
            flash('Category Successfully Edited %s' % editedCategory.name)
            return redirect(url_for('showCatalog'))
    else:
        return render_template('edit-category.html', category=editedCategory)

# Delete a category


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):

    if 'username' not in login_session:
        flash("""Please login to be able to delete category""")
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if categoryToDelete.user_id != login_session['user_id']:
        flash("""You are not authorized to delete this category.
            Please create your own category in order to delete.""")
        return redirect(url_for('showCategory', category_id=category_id))
    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('%s Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('delete-category.html',
                               category=categoryToDelete)


# Show Item

@app.route('/category/<int:category_id>/item/<int:item_id>')
def showItem(category_id, item_id):
    category = session.query(Category).filter_by(id=category_id).one()
    item = session.query(Item).filter_by(id=item_id).one()
    return render_template('item-details.html', category=category, item=item)


# Create a new item
@app.route('/category/<int:category_id>/item/new/', methods=['GET', 'POST'])
def newItem(category_id):
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        selected_category_id = request.form['selected_category']
        category = session.query(Category).filter_by(
            id=selected_category_id).one()
        if category:
            if login_session['user_id'] != category.user_id:
                flash("""You are not authorized to add items to this category.
                    Please create your own category in order to add items.""")
                return redirect(url_for('showCategory',
                                        category_id=category_id))
            if (request.form['name'] and request.form['description']
                    and request.form['selected_category']):
                newItem = Item(name=request.form['name'],
                               description=request.form['description'],
                               category_id=selected_category_id,
                               user_id=category.user_id)
                session.add(newItem)
                session.commit()
                flash('New %s Item Successfully Created' % (newItem.name))
                return redirect(url_for('showItem', category_id=category.id,
                                        item_id=newItem.id))
        else:
            error = "One or more Invalid Values"
            categories = session.query(Category).filter_by(
                user_id=category.user_id).order_by(asc(Category.name))
            return render_template('new-item.html', categories=categories,
                                   category_id=category_id, error=error)
    else:
        category = session.query(Category).filter_by(id=category_id).one()
        if category:
            categories = session.query(Category).filter_by(
                user_id=category.user_id).order_by(asc(Category.name))
            return render_template('new-item.html', categories=categories,
                                   category_id=category_id)
        else:
            return url_for('showCatalog')


# Edit an Item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit/',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    if 'username' not in login_session:
        flash("Please login to be able to edit Item")
        return redirect('/login')

    if request.method == 'POST':
        selected_category_id = request.form['selected_category']
        category = session.query(Category).filter_by(
            id=selected_category_id).one()
        editedItem = session.query(Item).filter_by(id=item_id).one()
        if category:
            # check if user is authorized to edit this item
            if login_session['user_id'] != category.user_id:
                flash("""You are not authorized to Edit items to this category.
                    Please create your own category in order to Edit items.""")
                return redirect(url_for('showCategory',
                                        category_id=category_id))
            if (request.form['name'] and request.form['description']
                    and request.form['selected_category']):
                editedItem.name = request.form['name']
                editedItem.description = request.form['description']
                editedItem.category_id = request.form['selected_category']
                session.add(editedItem)
                session.commit()
                flash('Menu Item Successfully Edited')
                return redirect(url_for('showItem', category_id=category.id,
                                        item_id=editedItem.id))
        else:
            error = "One or more Invalid Values"
            categories = session.query(Category).filter_by(
                user_id=category.user_id).order_by(asc(Category.name))

            return render_template('edit-item.html', categories=categories,
                                   category_id=category_id, error=error)
    else:
        category = session.query(Category).filter_by(id=category_id).one()
        if category:
            if category.user_id == login_session['user_id']:
                editedItem = session.query(Item).filter_by(id=item_id).one()
                if editedItem.user_id == login_session['user_id']:
                    categories = session.query(Category).filter_by(
                        user_id=category.user_id).order_by(asc(Category.name))
                    return render_template('edit-item.html',
                                           categories=categories,
                                           category_id=category_id,
                                           item=editedItem)
                else:
                    flash("""You are not authorized to Edit items to this category.
                        Please create your own category in order to Edit items.""")
                    return redirect(url_for('showItem',
                                            category_id=category_id,
                                            item_id=item_id))
            else:
                flash("""You are not authorized to Edit items to this category.
                    Please create your own category in order to Edit items.""")
                return redirect(url_for('showItem',
                                        category_id=category_id,
                                        item_id=item_id))
        else:
            flash("""You are not authorized to Edit items to this category.
                Please create your own category in order to Edit items.""")
            return redirect(url_for('showItem',
                                    category_id=category_id,
                                    item_id=item_id))

# Delete a  item


@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    if 'username' not in login_session:
        flash("Please login to be able to delete item")
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if (login_session['user_id'] != category.user_id
            and login_session['user_id'] != itemToDelete.user_id):
        flash("""You are not authorized to Delete this Item.""")
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showCategory', category_id=category_id))
    else:
        return render_template('delete-item.html', item=itemToDelete)


# Login Panel


@app.route('/login/')
def showLogin():
    generate_csrf_token()
    return render_template("login.html")


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Obtain authorization code
    code = request.form.get('code')

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('g_secrets.json', scope='')
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

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['credentials'] = credentials
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
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = {'username': login_session[
        'username'], 'picture': login_session['picture']}
    flash("you are now logged in as %s" % login_session['username'])
    return jsonify(output)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():

    access_token = request.form.get('access_token')
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = """https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token
    &client_id=%s&client_secret=%s&fb_exchange_token=%s""" % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''

    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = """https://graph.facebook.com/v2.8/me?access_token=%s
    &fields=name,id,email""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = """https://graph.facebook.com/v2.8/me/picture?access_token=%s
    &redirect=0&height=200&width=200""" % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = {'username': login_session[
        'username'], 'picture': login_session['picture']}
    flash("Now logged in as %s" % login_session['username'])
    return jsonify(output)


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


# JSON APIs to view Category Items
@app.route('/category/<int:category_id>/items/JSON')
def categoryItemsJSON(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    categoryItem = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=categoryItem.serialize)


@app.route('/catalog/JSON')
def catalogJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categories])


if __name__ == '__main__':
    app.secret_key = 'supercalifragilisticexpialidocious'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
