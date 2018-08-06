# Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license. See LICENSE.txt in the project root for license information.
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from tutorial.authhelper import get_signin_url, get_token_from_code, get_access_token
from tutorial.outlookservice import get_me, get_my_messages, get_my_events, get_my_contacts, get_my_rooms, post_my_events, post_send_message
import time

# Create your views here.

def home(request):
  redirect_uri = request.build_absolute_uri(reverse('tutorial:gettoken'))
  sign_in_url = get_signin_url(redirect_uri)
  context = { 'signin_url': sign_in_url }
  return render(request, 'tutorial/home.html', context)
  
def gettoken(request):
  auth_code = request.GET['code']
  redirect_uri = request.build_absolute_uri(reverse('tutorial:gettoken'))
  token = get_token_from_code(auth_code, redirect_uri)
  access_token = token['access_token']
  user = get_me(access_token)
  refresh_token = token['refresh_token']
  expires_in = token['expires_in']

  # expires_in is in seconds
  # Get current timestamp (seconds since Unix Epoch) and
  # add expires_in to get expiration time
  # Subtract 5 minutes to allow for clock differences
  expiration = int(time.time()) + expires_in - 300
  
  # Save the token in the session
  request.session['access_token'] = access_token
  request.session['refresh_token'] = refresh_token
  request.session['token_expires'] = expiration

  return HttpResponseRedirect(reverse('tutorial:mail'))
  
def mail(request):
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  # If there is no token in the session, redirect to home
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    messages = get_my_messages(access_token)
    context = { 'messages': messages['value'] }
    return render(request, 'tutorial/mail.html', context)
    
def events(request):
  import ipdb;ipdb.set_trace()
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  # If there is no token in the session, redirect to home
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    events = get_my_events(access_token)
    context = { 'events': events['value'] }
    return render(request, 'tutorial/events.html', context)
    
def contacts(request):
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  # If there is no token in the session, redirect to home
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    contacts = get_my_contacts(access_token)
    context = { 'contacts': contacts['value'] }
    return render(request, 'tutorial/contacts.html', context)


def findmeetings(request):
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    meetings = post_find_meetings(access_token)
    context = { 'contacts': meetings['value'] }
    return render(request, 'tutorial/contacts.html', context)

def rooms(request):
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    rooms = get_my_rooms(access_token)
    context = { 'contacts': rooms['value'] }
    return render(request, 'tutorial/contacts.html', context)

def create_events(request):
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    events = post_my_events(access_token)
    context = { 'contacts': events['value'] }
    return render(request, 'tutorial/contacts.html', context)

def send_message(request):
  import ipdb;ipdb.set_trace()
  access_token = get_access_token(request, request.build_absolute_uri(reverse('tutorial:gettoken')))
  if not access_token:
    return HttpResponseRedirect(reverse('tutorial:home'))
  else:
    events = post_send_message(access_token)
    context = { 'contacts': events['value'] }
    return render(request, 'tutorial/contacts.html', context)


def skype_login(request):
  import requests
  import requests.auth as auth
  import json

  url = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"
  headers = {'Content-Type' : 'application/x-www-form-urlencoded', 'Host' : 'login.microsoftonline.com' }


  query_parameters = {
                      "grant_type": "client_credentials",
                      "client_id" : "6d0027b4-3198-4e7c-a22d-61cbc76b2fb3",
                      "client_secret": "zceMNEQQI190{{pekoY96+^",
                      "scope": "https://api.botframework.com/.default"
                    }

  # params = "grant_type=client_credentials&client_id=%s&client_secret=%s&scope=https%3A%2F%2Fapi.botframework.com%2F.default" %("6d0027b4-3198-4e7c-a22d-61cbc76b2fb3", "zceMNEQQI190{{pekoY96+^")
  r = requests.post(url, data=query_parameters)
  print(r.content)

  jsonAuth = json.loads(r.content.decode('utf-8'))

  print(jsonAuth['token_type'] + ' ' + jsonAuth['access_token'])

  headers2 = {'Authorization' : 'Bearer ' + jsonAuth['access_token'], 'Content-Type':'application/json' }

  url='https://smba.trafficmanager.net/apis/v3/conversations/8:roshinraj007/members'

  req = requests.get(url, headers=headers2)

  print(req.content)