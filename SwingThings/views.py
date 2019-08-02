"""
Routes and views for the flask application.
"""

#Packages
from datetime import datetime
from flask import render_template, request, redirect, jsonify
from SwingThings import app
import requests
import json
import urllib.request 
import urllib.parse 
import random
import math
from http import cookies


#Variables
#Credentials here
stateKey = 'spotify_auth_state'
C = cookies.SimpleCookie()
user_access_token = ''

#Functions
def generateRandomString(length):
    string = ""
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    i = 0
    return ''.join(random.choice(characters) for i in range(length))

#Routes
@app.route('/')
@app.route('/index')
def index():
    """Renders the home page."""
    return render_template(
        'index.html',
        title='Swing Things',
        #year=datetime.now().year,
   )


@app.route('/login')
def login():
    #generate a unique random state for the user
    state = generateRandomString(16)

    #save it into the cookies
    #C = cookies.SimpleCookie()
    C[stateKey] = state

    #redirect the user to the spotify authorize page
    scope = 'user-read-private user-read-email playlist-read-private playlist-read-collaborative'
    query = {
        'response_type': 'code',
        'client_id': client_id,
        'scope': scope,
        'redirect_uri': redirect_uri,
        'state': state    
    }
    query_string = urllib.parse.urlencode(query) 
    url = ('https://accounts.spotify.com/authorize?' + query_string)
    return redirect(url)


@app.route('/callback')
def callback():
    #get the code and the state from the url
    code = request.args.get('code')
    state = request.args.get('state')
    
    #check the state that was saved in the cookies
    #c = cookies.SimpleCookie()
    storedState = C[stateKey].value

    #print('storedState:', storedState)
    #print('state:', state)
    #print('storedState with value', storedState.value)

    #used the storedstate to make sure that it's the same as the one in the url
    if state == None or state != storedState:
        query = {
            'error' : 'state_mismatch'
        }
        query_string = urllib.parse.urlencode(query) 
        return redirect('/#' + query_string)
    else:
        #the stored state is valid. give the user an access token
        #clear the cookies since the stored state is no longer needed
        C.clear()

        #set up the query
        client_auth = requests.auth.HTTPBasicAuth(client_id, client_secret)
        post_data = {
            'grant_type': 'authorization_code',
		    'code': code,
		    'redirect_uri': redirect_uri
        }

        #make the post in order to get the access token
        response = requests.post('https://accounts.spotify.com/api/token', auth = client_auth, data = post_data)
        
        #check if we were successful
        if response.status_code == 200:
            #if we are successful, get the token
            token_json = response.json()
            token = token_json["access_token"]

            global user_access_token 
            user_access_token = token_json["access_token"]

            #print(token_json["access_token"])

            #pass the token to the browser URL
            query = {
                'access_token': token
            }
            query_string = urllib.parse.urlencode(query) 

            #get the user's id

            return redirect('/#' + query_string)
        else:
            #if we were not successful, redirect to an error page
            query = {
                'error': 'invalid_token'
            }
            query_string = urllib.parse.urlencode(query) 
            return redirect('/#' + query_string)
    return ('we made it')



@app.route('/user')
def get_user_info():
    header = {
        'Authorization': 'Bearer ' + user_access_token
    }
    #print('header is:', header)
    #print('access token is:', user_access_token)
    response = requests.get('https://api.spotify.com/v1/me', headers = header)
   
   #check for errors

    user_info_json = response.json()
    return jsonify(user_info_json)


def get_user_id():
    json_info = get_user_info()
    info = json_info.get_json()
    return info['id'];


@app.route('/playlists')
def get_playlists():
    #set up the get resquest
    header = {
        'Authorization': 'Bearer ' + user_access_token
    }
    user_id = get_user_id()
    url = "https://api.spotify.com/v1/users/" + user_id + "/playlists"
    response = requests.get(url, headers = header)
   
   #check for errors

    user_info_json = response.json()
    return jsonify(user_info_json)


@app.route('/playlist_info/<string:id>/<int:tracks>')
def get_playlist_info(id, tracks):
    #set up the get request
    header = {
        'Authorization': 'Bearer ' + user_access_token
    }
    

    #if there are more than 100 tracks, then loop until we get all the tracks
    offset = 0
    json_list = []
    loops = math.ceil(tracks / 100)
    for x in range(0, loops):
        query = {
            'fields': 'items(track(name, popularity, id, explicit, album, artists))',
            'offset': offset
        }
        query_string = urllib.parse.urlencode(query) 
        url = "https://api.spotify.com/v1/playlists/" + id +"/tracks" + query_string
        #make the request
        response = requests.get(url, headers = header)
        data = response.json()
        json_list.append(data)
        print(data)

        #change the offset
        offset += len(data["items"]) - 1
        #dont forget to check for errors!

    #return the final json
    json_final = json.dumps(json_list)
    return jsonify(json_final)