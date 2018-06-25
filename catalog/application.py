#!/usr/bin/env python
from flask import Flask, render_template, request
from flask import redirect, url_for, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc
from app_db import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# variable to determine whether logged in fb or google
logout_var = 0
app = Flask(__name__)
engine = create_engine('sqlite:///onlineshopping.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Web Client Shopping"


# login method contains login page which contains google and facebook login
@app.route('/login')
def login():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    if 'username' in login_session:
        return render_template('loggedin_home.html',
                               categories=categories,
                               items=items,
                               log=login_session['username'],
                               log_type=logout_var)
    else:
        return render_template('login.html', STATE=state)


# google plus sign in method
@app.route('/gconnect', methods=['POST'])
def gconnect():
    global logout_var
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
        response = make_response(json.dumps('already connected.'),
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

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    print "done!"
    output = 'done'
    logout_var = 1
    return output


# google plus sign out method
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
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
        return redirect(url_for('homePage'))
    else:
        response = make_response(json.dumps('Failed to revoke token.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# facebook connect method
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    global logout_var
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type'
           '=fb_exchange_token&client_id'
           '=%s&client_secret=%s&fb_exchange_token=%s' % (
            app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')
    url = ('https://graph.facebook.com/v2.8/me?access_token'
           '=%s&fields=name,id,email' % token)
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
    url = ('https://graph.facebook.com/v2.8/me/picture?access_token'
           '=%s&redirect=0&height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; '
    output += ' height: 300px; '
    output += ' border-radius: 150px; '
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    logout_var = 2
    return output


# fb disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s'
           % (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['provider']
        del login_session['username']
        del login_session['email']
        del login_session['facebook_id']
        del login_session['access_token']
        return redirect(url_for('homePage'))
    else:
        response = make_response(json.dumps('Failed to revoke token.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# create new account for new user associated with social account
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
        user = session.query(User).filter_by(email=email).first()
        return user.id


# JSON endpoint
@app.route('/CategoriesJSON')
def CategoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[i.serialize for i in categories])


@app.route('/ItemsJSON')
def ItemsJSON():
    Items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in Items])


@app.route('/CategoriesItemsJSON')
def CategoriesItemsJSON():
    categories = session.query(Category).all()
    Items = session.query(Item).all()
    return jsonify(categories=[i.serialize for i in categories],
                   items=[x.serialize for x in Items])


# default route the homepage
@app.route('/')
@app.route('/home')
def homePage():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # navigate to logged in page if user is already logged in
    if 'username' in login_session:
        return render_template('loggedin_home.html',
                               categories=categories,
                               items=items,
                               log=login_session['username'],
                               log_type=logout_var)
    else:
        return render_template('home.html',
                               categories=categories,
                               items=items,
                               STATE=state)


# homepage for logged in users
@app.route('/loggedin_home')
def loggedin_home():
    categories = session.query(Category).all()
    # fetch the latest 10 items added
    items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    # create random state
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    if 'username' not in login_session:
        return render_template('home.html',
                               categories=categories,
                               items=items,
                               STATE=state)
    else:
        return render_template('loggedin_home.html',
                               categories=categories,
                               items=items,
                               log=login_session['username'],
                               log_type=logout_var)


# show all items related to specific category
@app.route('/category/<int:category_id>')
def showItems(category_id):
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(category_id=category_id).all()
    specific_category = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                        for x in xrange(32))
        login_session['state'] = state
        return render_template('publicitems.html',
                               items=items,
                               categories=categories,
                               specific_category=specific_category,
                               STATE=state)
    # if logged in navigate to the item page which contains CRUD operations
    else:
        return render_template('items.html',
                               items=items,
                               categories=categories,
                               specific_category=specific_category,
                               log=login_session['username'],
                               log_type=logout_var)


# add new item to specific category
@app.route('/category/<int:category_id>/item/new', methods=['GET', 'POST'])
def addItem(category_id):
    if 'username' in login_session:
        if request.method == 'POST':
            new_item = Item(name=request.form['name'],
                            description=request.form['description'],
                            price=request.form['price'],
                            item_state=request.form['item_state'],
                            category_id=category_id,
                            user_id=login_session['user_id'])
            session.add(new_item)
            session.commit()
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return render_template('addItem.html',
                                   category_id=category_id,
                                   log=login_session['username'],
                                   log_type=logout_var)
    else:
        output = "'<script>function myFunction() {alert('not authorized');}"
        output += "</script><body onload='myFunction()'>"
        return output


# show details of specific item
@app.route('/category/<int:category_id>/item/<int:item_id>')
def showitemDetails(item_id, category_id):
    item = session.query(Item).filter_by(id=item_id).one()
    categories = session.query(Category).all()
    specific_category = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return render_template('publicitem_details.html',
                               item=item,
                               categories=categories)
    else:
        return render_template('item_details.html',
                               item=item,
                               categories=categories,
                               specific_category=specific_category,
                               log=login_session['username'],
                               log_type=logout_var)


# delete speific item
@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(item_id, category_id):
    if 'username' in login_session:
        itemtodelete = session.query(Item).filter_by(id=item_id).one()
        category = session.query(Category).filter_by(id=category_id).one()
    # if the deleted item is not user's owner so delete operation is denied
        if login_session['user_id'] != itemtodelete.user_id:
            output = "'<script>function myFunction() {alert('not authorized');"
            output += "}</script><body onload='myFunction()'>"
            return output
        if request.method == 'POST':
            session.delete(itemtodelete)
            session.commit()
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return render_template('deleteitem.html',
                                   category_id=category_id,
                                   item_id=item_id,
                                   item=itemtodelete,
                                   log=login_session['username'],
                                   log_type=logout_var)
    else:
        output = "'<script>function myFunction() {alert('not authorized');}"
        output += "</script><body onload='myFunction()'>"
        return output


# edit the internal details of specific item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(item_id, category_id):
    if 'username' in login_session:
        itemtoedit = session.query(Item).filter_by(id=item_id).one()
        category = session.query(Category).filter_by(id=category_id).one()
    # if the edited item is not user's owner so edit operation is denied
        if login_session['user_id'] != itemtoedit.user_id:
            output = "<script>function myFunction() {alert('not authorized');}"
            output += "</script><body onload='myFunction()'>"
            return output
        if request.method == 'POST':
            itemtoedit.name = request.form['name']
            itemtoedit.description = request.form['description']
            itemtoedit.price = request.form['price']
            itemtoedit.item_state = request.form['item_state']
            session.add(itemtoedit)
            session.commit()
            return redirect(url_for('showItems', category_id=category_id))
        else:
            return render_template('edititem.html',
                                   category_id=category_id,
                                   item_id=item_id, item=itemtoedit,
                                   log=login_session['username'],
                                   log_type=logout_var)
    else:
        output = "'<script>function myFunction() {alert('not authorized');}"
        output += "</script><body onload='myFunction()'>"
        return output


# main function to execute includes the local host port
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
