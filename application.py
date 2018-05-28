#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, render_template, request
from flask import redirect, url_for, flash, jsonify
from database_setup import Base, Category, CategoryItem
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
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

CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']
APPLICATION_NAME = 'Item Catalog App'

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token

    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'
                                            ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code

    code = request.data

    try:

        # Upgrade the authorization code into a credentials object

        oauth_flow = flow_from_clientsecrets('client_secrets.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = \
            make_response(json.dumps('''
            Failed to upgrade the authorization code.'''), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.

    access_token = credentials.access_token
    url = \
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        % access_token
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
        response = \
            make_response(json.dumps("""
            Token's user ID doesn't match given user ID."""), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.

    if result['issued_to'] != CLIENT_ID:
        response = \
            make_response(json.dumps("Token's client ID does not match app's."
                                     ), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = \
            make_response(json.dumps('Current user is already connected.'
                                     ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info

    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += \
        ''' " style = "width: 300px; height: 300px;
        border-radius: 150px;-webkit-border-radius: 150px;
        -moz-border-radius: 150px;"> '''
    flash('you are now logged in as %s' % login_session['username'])
    print 'done!'
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = \
            make_response(json.dumps('Current user not connected.'),
                          401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
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
        response = make_response(json.dumps('Successfully disconnected.'
                                            ), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = \
            make_response(json.dumps('Failed to revoke token for given user.',
                                     400))
        response.headers['Content-Type'] = 'application/json'
        return make_response


# an API Endpoint (Get Request)

@app.route('/categories/<int:category_id>/JSON')
def categoryItemsJSON(category_id):
    try:
        categoryItems = \
            session.query(CategoryItem).filter_by(category_id=category_id)
        return jsonify(CategoryItems=[i.serialize for i in
                       categoryItems])
    except:
        return 'This category has no items yet'


@app.route('/categories/<int:category_id>/<int:category_item_id>/JSON')
def itemDescriptionJSON(category_id, category_item_id):
    try:
        itemDescription = \
            session.query(CategoryItem).\
            filter_by(category_id=category_id).\
            filter_by(id=category_item_id)
        return jsonify(ItemDescription=[i.serialize for i in
                       itemDescription])
    except:
        return 'This item has no description yet'


@app.route('/')
@app.route('/categories')
def Categories():
    categories = session.query(Category).all()
    return render_template('catalog.html', categories=categories)


@app.route('/categories/<int:category_id>/')
def categoryItems(category_id):
    try:
        categoryItems = \
            session.query(CategoryItem).filter_by(category_id=category_id)
        return render_template('category.html',
                               category_items=categoryItems,
                               category_id=category_id)
    except:
        if 'username' not in login_session:
            return redirect('/login')
        return render_template('new_category_item.html',
                               category_id=category_id)


@app.route('/categories/<int:category_id>/<int:category_item_id>/')
def itemDescription(category_id, category_item_id):
    try:
        itemDescription = \
            session.query(CategoryItem).\
            filter_by(category_id=category_id).\
            filter_by(id=category_item_id)
        return render_template('item_description.html',
                               item_description=itemDescription,
                               category_id=category_id,
                               id=category_item_id)
    except:
        return 'This item has no description yet'


@app.route('/categories/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Category(name=request.form['name'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('Categories'))
    else:
        return render_template('new_category.html')


@app.route('/categories/<int:category_id>/edit/', methods=['GET', 'POST'
                                                           ])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('Categories'))
    else:
        return render_template('edit_category.html', id=category_id,
                               item=editedItem)


@app.route('/categories/<int:category_id>/delete/', methods=['GET',
           'POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = \
        session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('Categories'))
    else:
        return render_template('category_delete_confirmation.html',
                               item=itemToDelete)


@app.route('/categories/<int:category_id>/new/', methods=['GET', 'POST'
                                                          ])
def newCategoryItem(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = CategoryItem(name=request.form['name'],
                               description=request.form['description'],
                               category_id=category_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('categoryItems',
                        category_id=category_id))
    else:
        return render_template('new_category_item.html',
                               category_id=category_id)


@app.route('/categories/<int:category_id>/<int:category_item_id>/edit/',
           methods=['GET', 'POST'])
def editCategoryItem(category_id, category_item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = \
        session.query(CategoryItem).filter_by(id=category_item_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
            session.add(editedItem)
            session.commit()
        if request.form['description']:
            editedItem.description = request.form['description']
            session.add(editedItem)
            session.commit()
        return redirect(url_for('categoryItems',
                        category_id=category_id))
    else:
        return render_template('edit_category_item.html',
                               category_id=category_id, item=editedItem)


@app.route('/categories/<int:category_id>/<int:category_item_id>/delete/',
           methods=['GET', 'POST'])
def deleteCategoryItem(category_id, category_item_id):
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = \
        session.query(CategoryItem).filter_by(id=category_item_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('categoryItems',
                        category_id=category_id))
    else:
        return render_template('delete_confirmation.html',
                               item=itemToDelete)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
