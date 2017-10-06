#!/usr/bin/env python3
# Flask imports
from functools import wraps

import os
from flask import Flask, render_template, request, redirect, url_for, flash, \
    jsonify

# sign in imports
from flask import session as login_session
import random
import string
# converts the info to real response to be send off to client
from flask import make_response
# authorization imports
# this import contains clientsecrets clientid and other parameters
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

# similar to urllib2 but with few improvements
import requests
# Database imports
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

app = Flask(__name__)
# 'postgresql://catalog:password@localhost/catalog'
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

Client_ID = json.loads(open(os.path.join('client_secrets.json'), 'r').read())['web'][
    'client_id']
APPLICATION_NAME = "Category Application"


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' in login_session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('showLogin'))

    return decorated_function


# function to create user
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
        'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one()
    return user.id


# function to get user info
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# function to get user id
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# create a state token and add to session for further validation
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    print(login_session)
    login_session['state'] = state
    print("The current session state is %s" % login_session['state'])
    return render_template('login.html', STATE=state)


# to create connection to google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # confirms that our user is making request rather than a malicious script
    print("*")
    print(request.args.get('state'))
    print(login_session)

    if request.args.get('state') != login_session['state']:
        print("***")
        response = make_response(json.dumps('Invaid state Parameter'), 401)
        response.headers['Content-type'] = 'applictaion/json'
        return response
    code = request.data
    try:
        print("**")
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        print(oauth_flow)
        # to specify that this is one time code
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
        print(credentials)
    except FlowExchangeError:
        response = make_response(
            json.dumps("Failed to upgrade authorization code"), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # check if access token is valid
    access_token = credentials.access_token
    print(access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http().request(url, 'GET')[1].decode()
    print(h)
    result = json.loads(h)
    print(result)

    # check for errors
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-type'] = 'application/json'

    # verify that the tokens match
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user id do not match"), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # verify client id's
    if result['issued_to'] != Client_ID:
        response = make_response(
            json.dumps("Token's Client id do not match"), 401)
        response.headers['Content-type'] = 'application/json'
        return response

    # if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and stored_gplus_id == gplus_id:
        response = make_response(
            json.dumps("User is already logged in"), 200)
        response.headers['Content-type'] = 'application/json'

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

    user_id = getUserID(data['email'])
    if not user_id:
        add_user = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius: 150px;-moz-border-radius: ' \
              '150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print
    "done!"
    return output


# to disconnect
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % \
          login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        print(login_session)
        login_session.clear()
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('category'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# api end points
# @app.route('/categories/subcategories/total/json')
# def total_to_json():
#     if 'username' in login_session:
#         result_r = session.query(Restaurant).all()
#         result_i = session.query(MenuItem).all()
#         result_t = session.query(Restaurant, MenuItem).join(MenuItem)
#         output = ""
#         for part_result in result_t:
#             jsonify([result.serialize for result in part_result])
#
#         return render_template('total_json.html', result_t=result_t)
#     else:
#         return redirect(url_for('showLogin'))

# api end points
@app.route('/categories/subcategories/json')
@login_required
def subcategories_to_json():
    result_i = session.query(MenuItem).all()
    output = ""
    return jsonify(results=[result.serialize for result in result_i])


# api end points
@app.route('/categories/json')
@login_required
def categories_to_json():
    results = session.query(Restaurant).all()
    return jsonify(results=[result.serialize for result in results])


# api end points
@app.route('/categories/<int:cat_id>/subcategories/json')
@login_required
def particular_subcategories_to_json(cat_id):
    results = session.query(MenuItem).filter_by(restaurant_id=cat_id)
    output = ""
    return jsonify(results=[result.serialize for result in results])


# api end points
@app.route('/categories/<int:cat_id>/subcategories/<int:sub_id>/json')
@login_required
def particular_subcategory_to_json(cat_id, sub_id):
    results = session.query(MenuItem).filter_by(restaurant_id=cat_id,
                                                id=sub_id)
    output = ""
    return jsonify(results=[result.serialize for result in results])


# categories
@app.route('/')
@app.route('/category/')
def category():
    # print(login_session['username']
    category_list = session.query(Restaurant).all()
    return render_template('category_list.html',
                           category_list=category_list,
                           login_session=login_session)


# add new category
@app.route('/category/new', methods=['POST', 'GET'])
@login_required
def newCategory():
    if request.method == 'POST':
        new_category = Restaurant(name=request.form['name'],
                                  user_id=login_session['user_id'])
        session.add(new_category)
        session.commit()
        return redirect(url_for('category'))
    else:
        return render_template('category_new.html',
                               login_session=login_session)


# to be implemented

# @app.route('/category/<int:cat_id>/edit', methods=['POST', 'GET'])
# def editCategory(cat_id):
#     return "edit category %s" % cat_id
#
#
# @app.route('/category/<int:cat_id>/delete', methods=['POST', 'GET'])
# def deleteCategory(cat_id):
#     return "delete category %s" % cat_id


# subcategory
# Sub Category


# delete existing category

@app.route('/category/<int:cat_id>/delete')
@login_required
def deleteCategory(cat_id):
    delete = session.query(Restaurant).filter_by(id=cat_id).first()
    if login_session['user_id'] == delete.user_id:
        session.delete(delete)
        session.commit()
        return " " + delete.name + " deleted!!<br> <a href = ''>here</a>"
    else:
        return "You are not authorized to do so!!"


# list subcategory
@app.route('/category/<int:cat_id>/subcategory/')
def subCategory(cat_id):
    category = session.query(Restaurant).filter_by(id=cat_id).first()
    subCategory_list = session.query(MenuItem).filter_by(
        restaurant_id=cat_id)
    print(category.name)
    print(subCategory_list)
    return render_template('sub_category_list.html', cat_id=cat_id,
                           category=category,
                           subCategory_list=subCategory_list,
                           login_session=login_session)


# add new subcategory
@app.route('/category/<int:cat_id>/subcategory/new',
           methods=['GET', 'POST'])
@login_required
def newSubCategory(cat_id):
    if request.method == 'POST':
        item = MenuItem(name=request.form['name'],
                        course=request.form['course'],
                        price=request.form['price'],
                        description=request.form['description'],
                        restaurant_id=cat_id,
                        user_id=login_session['user_id'])
        session.add(item)
        session.commit()
        return redirect(url_for('subCategory', cat_id=cat_id))
    else:
        return render_template('sub_category_new.html', cat_id=cat_id,
                               login_session=login_session)


# edit subcategory
@app.route('/category/<int:cat_id>/subcategory/<int:sub_id>/edit',
           methods=['POST', 'GET'])
@login_required
def editSubCategory(cat_id, sub_id):
    item = session.query(MenuItem).filter_by(restaurant_id=cat_id,
                                             id=sub_id).first()
    # authorization check
    if login_session['user_id'] == item.user_id:
        if request.method == 'POST':

            item.name = request.form['name']
            item.description = request.form['description']
            item.course = request.form['course']
            item.price = request.form['price']
            session.commit()
            return redirect(
                url_for('subCategory', cat_id=cat_id,
                        login_session=login_session))
        else:
            item = session.query(MenuItem).filter_by(id=sub_id,
                                                     restaurant_id=cat_id).first()
            return render_template('sub_category_edit.html', cat_id=cat_id,
                                   sub_id=sub_id, items=item,
                                   login_session=login_session)
    else:
        return "You are not authorized to edit this menu!!"


@app.route('/category/<int:cat_id>/subcategory/<int:sub_id>/delete',
           methods=['POST', 'GET'])
@login_required
def deleteSubCategory(cat_id, sub_id):
    item = session.query(MenuItem).filter_by(restaurant_id=cat_id,
                                             id=sub_id).first()
    # authorization check
    if login_session['user_id'] == item.user_id:
        if request.method == 'POST':
            # item = session.query(MenuItem).filter_by(restaurant_id=cat_id,
            #    id=sub_id).first()
            session.delete(item)
            session.commit()
            return redirect(
                url_for('subCategory', cat_id=cat_id,
                        login_session=login_session))
        else:
            item = session.query(MenuItem).filter_by(id=sub_id,
                                                     restaurant_id=cat_id).first()
            return render_template('sub_category_delete.html',
                                   cat_id=cat_id,
                                   sub_id=sub_id, items=item,
                                   login_session=login_session)
    else:
        return "Your are not authorized to delete this menu!!"


# details to be implemented
# @app.route('/category/<int:cat_id>/subcategory/<int:sub_id>/details/')
# def details(cat_id, sub_id):
#     return "/category/%s/subcategory/%s/details/" % (cat_id, sub_id)

# called on the execution to host server on 8000
if __name__ == '__main__':
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host='localhost', port=8000)
