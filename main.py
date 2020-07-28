# -*- coding: utf-8 -*-
# !/usr/bin/env python
import time, datetime
import requests, jwt, json
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from firebase_admin import auth
from firebase_admin import exceptions
from flask import Flask, render_template, redirect, request, jsonify, abort

from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_mobility import Mobility

import hashlib
import hmac

import config

'''
config.py

csrf_sc = b''

liquid_id = ''
liquid_sc = ''

bitkub_ky_demo = ''
bitkub_sc_demo = ''

bitkub_ky = ''
bitkub_sc = ''
'''

app = Flask(__name__,
  static_url_path='',
  static_folder='static',
  template_folder='templates')
app.config['SECRET_KEY'] = config.csrf_sc
# app.config['WTF_CSRF_TIME_LIMIT'] = 30

Mobility(app)
csrf = CSRFProtect(app)

# https://medium.com/faun/getting-started-with-firebase-cloud-firestore-using-python-c6ab3f5ecae0
cred = credentials.Certificate('serviceAccountKey.json')
firebase_admin.initialize_app(cred)

db = firestore.client()
mbr_col = db.collection('members')
trd_col = db.collection('trading')
trt_col = db.collection('transactions')

_title = 'Morbucks Trading Club Platform BETA 02.'


@app.before_request
def force_https():
  # return 'This page is maintenance.'
  # pass
  if request.endpoint in app.view_functions and not request.is_secure:
    return redirect(request.url.replace('http://', 'https://'))


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
  print(e)
  return e
  # return render_template('csrf_error.html', reason=e.description), 400


@app.route('/__csrf', methods=['GET', 'POST'])
def __csrf():
  if '_session' in request.cookies:
    return jsonify({'csrf': render_template('__csrf.html')})
  else:
    return jsonify({'csrf': '0'})


@app.route('/socket', methods=['GET', 'POST'])
def socket():
  return render_template('websocket.html')


@app.route('/signin', methods=['GET', 'POST'])
def signin():
  return render_template('signin.html', title=_title)


@app.route('/csrf', methods=['POST'])
def login():
  if '_session' in request.cookies:
    return jsonify({'status': 'success'})
  # Get the ID token sent by the client
  id_token = request.json['idToken']
  # To ensure that cookies are set only on recently signed in users, check auth_time in
  # ID token before creating a cookie.
  try:
    decoded_claims = auth.verify_id_token(id_token)

    uid = decoded_claims['uid']
    user = auth.get_user(uid)
    print('Successfully fetched user data: {0}'.format(user.email))
    # Only process if the user signed in within the last 5 minutes.
    if time.time() - decoded_claims['auth_time'] < 5 * 60:
      expires_in = datetime.timedelta(days=5)
      expires = datetime.datetime.now() + expires_in
      session_cookie = auth.create_session_cookie(id_token, expires_in=expires_in)
      response = jsonify({'status': 'success'})

      response.set_cookie(
        '_session', session_cookie, expires=expires, httponly=True, secure=True)

      return response

    # User did not sign in recently. To guard against ID token theft, require
    # re-authentication.
    return abort(401, 'Recent sign in required')
  except auth.InvalidIdTokenError:
    return abort(401, 'Invalid ID token')
  except exceptions.FirebaseError:
    return abort(401, 'Failed to create a session cookie')


@app.route('/bitkub_books', methods=['GET', 'POST'])
def bitkub_book():
  url = 'https://api.bitkub.com/api/market/books' + request.json['query']
  res = requests.get(url)
  data_ = json.loads(res.text)
  return data_


@app.route('/bitkub_token', methods=['GET', 'POST'])
def bitkub_token():
  # https://api.bitkub.com/api/market/symbols

  url = 'https://api.bitkub.com/api/market/wstoken'
  ts = int(time.time())
  payload = {'ts': ts}

  # payload_ = json.dumps(payload, separators=(',', ':'), sort_keys=True)
  payload_ = json.dumps(payload)

  signature = hmac.new(config.bitkub_sc.encode(), payload_.encode(), digestmod=hashlib.sha256).hexdigest()

  payload['sig'] = signature
  headers = {'accept': 'application/json', 'content-type': 'application/json', 'x-btk-apikey': config.bitkub_ky}
  res = requests.post(url, json=payload, headers=headers)
  data_ = json.loads(res.text)
  return data_


@app.route('/uid_move', methods=['GET', 'POST'])
def uid_move():
  return jsonify({'message': 'test'})
  email_ = 'chok_jk@yahoo.com'

  facebook_rm = db.collection('facebook_remove').document(email_).get()

  if facebook_rm.exists:
    print('exist')
    trading_col = db.collection('trading')
    fb_uid = facebook_rm.to_dict()['uid']
    members_uid_ = trading_col.document('ClubFeedXRP_hand').get().to_dict()

    if fb_uid in members_uid_:
      print('exist in ClubFeedXRP_hand')

    members_uid_ = trading_col.document('LiquidTeam').get().to_dict()

    if fb_uid in members_uid_:
      print('exist in LiquidTeam')
      old_uid = members_uid_[fb_uid]
      print(old_uid)
      trading_col.document('LiquidTeam').update({
        'test': old_uid
      })

  return jsonify({'message': 'test'})


@app.route('/facebook_remove', methods=['GET', 'POST'])
def facebook_remove():
  return jsonify({'message': 'test'})
  fbr_col = db.collection('facebook_remove')
  fb = {
    "natawat_n@hotmail.co.th": "4UXlnMQNtXQa3YEOKkcNqCKSRB13",
    "candles-88@hotmail.com": "EFH8R82sn4XeZINaErubZwbISQu1",
    "chok_jk@yahoo.com": "OqPxZIpWkbReZOecLR0Vs7ufKCr1",
    "tanapat444@hotmail.com": "Or8QCTnZIFeJquHK9IXgmseDAbx1",
    "poraweat04@hotmail.com": "T7fiBeIIIqdVERCtO0kumS1KqHh1",
    "pongsakorn_1745@hotmail.com": "cM5OM69XOXPWQr6uLKAjCfzp2td2",
    "hkongs@yahoo.co.th": "gHJTmys65Kcxiw6rLCuSyDmiCYD3",
    "taff_ads@yahoo.com": "jaTXYrDEsSfabe4QOvvvNvaMRU53",
    "dogcia@gmail.com": "mzq9NlO3l8MgWddJw2MNcJ2waIk2",
    "angelrosefb2018@gmail.com": "nFEKJcngIzZ1xuqXT8431v9Glfz1",
    "mark_ai01@hotmail.com": "xkeDtlzLjeXGTkB88QaKz09g7fI3"
  }

  for email in fb:
    fbr_col.document(email).set({
      'uid': fb[email]
    })
  return jsonify({'message': 'test'})


@app.route('/list_members', methods=['GET', 'POST'])
def list_members():
  return jsonify({'message': 'test'})
  session_cookie = request.cookies.get('_session')
  decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)

  mbr_data = mbr_col.document(decoded_claims['email']).get().to_dict()
  print('test')
  if mbr_data['ident'] > 55:
    result = auth.list_users()

    for user in result.users:
        print('"'+user.email+'": "'+user.uid+'"')

  return jsonify({'message': 'test'})


@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
  try:
    session_cookie = request.cookies.get('_session')
    decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
    mbr_data = mbr_col.document(decoded_claims['email']).get().to_dict()

    # DemoTrade
    if request.json['trade'] == 'demotrade' and request.json['desire'] == 'create':
      _email = decoded_claims['email']
      trd_doc = trd_col.document('DemoTrade')

      try:
        uid_ = auth.get_user_by_email(_email).uid
        trd_doc.update({
          uid_: {'email': _email, 'cashflow': 0}
        })

        if mbr_data == None:
          mbr_col.document(_email).set({
            'ident': 1,
            'trading': ['DemoTrade']
          })
        else:
          mbr_col_get = mbr_col.document(_email).get().to_dict()
          if 'DemoTrade' not in mbr_col_get['trading']:
            mbr_col_get['trading'].append('DemoTrade')
            mbr_col.document(_email).update(mbr_col_get)

        try:
          bullets_len = len(mbr_col.document(_email).collection('trading').document('DemoTrade').get().to_dict())
        except Exception as e:
          print(e)
          bullets_len = 0

        res = requests.get('https://api.bitkub.com/api/market/asks?sym=thb_xrp&lmt=1')
        data_ = json.loads(res.text)
        offer_a = data_['result'][0][3]
        offer_b = (int(offer_a) / 100) * 90
        add_data = {}

        for i in range(20):
          if i < 5:
            offer = offer_a
          elif i >= 5 and i < 10:
            offer = offer_b
          else:
            offer = ''

          add_data.update({
            str(i+bullets_len+1): {'amount': 5, 'status': 'Bought', 'comment': '', 'sell': '', 'buy': offer},
          })

        exists_ = mbr_col.document(_email).get()

        if not exists_.exists:
          mbr_col.document(_email).set({})

        add_member_doc = mbr_col.document(_email).collection('trading').document('DemoTrade_bullets')

        if bullets_len == 0:
          add_member_doc.set(add_data)
        else:
          add_member_doc.update(add_data)

        return jsonify({'message': 'created'})

      except Exception as e:
        print(e)
        return jsonify({'message': 'No member'})

    if request.json['trade'] == 'demotrade' and request.json['desire'] == 'remove':
      _email = decoded_claims['email']
      trd_doc = trd_col.document('DemoTrade')

      try:
        uid_ = auth.get_user_by_email(_email).uid

        # trd_doc.delete()
        trd_get = mbr_col.document(_email).get().to_dict()
        trd_get['trading'].remove('DemoTrade')
        mbr_col.document(_email).update(trd_get)
        exists_ = mbr_col.document(_email).get()
        return jsonify({'message': 'removed'})

      except Exception as e:
        print(e)
        return jsonify({'message': 'No member'})

    # DemoTrade#

    if mbr_data['ident'] > 5:

      # ClubFeedXRP_hand
      if request.json['trade'] == 'ClubFeedXRP_hand':
        _email = request.json['email'].lower()
        trd_doc = trd_col.document('ClubFeedXRP_hand')

        try:
          uid_ = auth.get_user_by_email(_email).uid
          if request.json['cashflow'] != None:
            trd_doc.update({
              uid_: {'email': _email, 'ident': request.json['ident'], 'cashflow': request.json['cashflow']}
            })

          try:
            bullets_len = len(
              mbr_col.document(_email).collection('trading').document('ClubFeedXRP_hand_bullets').get().to_dict())
          except Exception as e:
            print(e)
            bullets_len = 0

          add_data = {}
          if request.json['price'] == None:
            buy_ = ''
          else:
            buy_ = request.json['price']

          for i in range(int(request.json['bullet'])):
            add_data.update({
              str(i+bullets_len+1): {'amount': request.json['amount'], 'status': 'Bought', 'comment': '', 'sell': '', 'buy': buy_},
            })

          exists_ = mbr_col.document(_email).get()
          if not exists_.exists:
            mbr_col.document(_email).set({})

          add_member_doc = mbr_col.document(_email).collection('trading').document('ClubFeedXRP_hand_bullets')

          if bullets_len == 0:
            add_member_doc.set(add_data)
          else:
            add_member_doc.update(add_data)

          return jsonify({'message': 'success'})

        except Exception as e:
          print(e)
          return jsonify({'message': 'No member'})
      # ClubFeedXRP_hand#
      # ClubFeedXRP_bot
      elif request.json['trade'] == 'ClubFeedXRP_bot':
        _email = request.json['email'].lower()
        trd_doc = trd_col.document('ClubFeedXRP_bot')

        try:
          uid_ = auth.get_user_by_email(_email).uid
          trd_doc.update({
            uid_: {'email': _email, 'ident': request.json['ident'], 'cashflow': request.json['cashflow']}
          })

          try:
            bullets_len = len(
              mbr_col.document(_email).collection('trading').document('ClubFeedXRP_bot_bullets').get().to_dict())
          except Exception as e:
            print(e)
            bullets_len = 0

          add_data = {}
          for i in range(int(request.json['bullet'])):
            add_data.update({
              str(i+bullets_len+1): {'amount': request.json['amount'], 'status': 'Bought', 'sell': '', 'buy': request.json['price'], 'sell_pending': 0, 'buy_pending': 0},
            })

          exists_ = mbr_col.document(_email).get()
          if not exists_.exists:
            mbr_col.document(_email).set({})

          add_member_doc = mbr_col.document(_email).collection('trading').document('ClubFeedXRP_bot_bullets')

          if bullets_len == 0:
            add_member_doc.set(add_data)
          else:
            add_member_doc.update(add_data)

          return jsonify({'message': 'success'})

        except Exception as e:
          print(e)
          return jsonify({'message': 'No member'})
        # ClubFeedXRP_bot#

      else:
        return jsonify({'message': 'error'})

  except Exception as e:
    print(e)
    return jsonify({'message': 'error'})


@app.route('/liquidteam_trans', methods=['GET', 'POST'])
def liquidteam_trans():
  now = int(datetime.datetime.timestamp(datetime.datetime.now()) * 1000)
  path = '/executions/me?product_id=83&limit=300&id=' + request.json['_id']
  auth_payload = {
    'path': path,
    'nonce': now,
    'token_id': config.liquid_id
  }
  signature = jwt.encode(auth_payload, config.liquid_sc, algorithm='HS256')

  headers = {
    'content-type': 'application/json',
    'X-Quoine-API-Versioncept': '2',
    'X-Quoine-Auth': signature
  }

  res = requests.get('https://api.liquid.com' + path, headers=headers)
  data_ = json.loads(res.text)
  return jsonify({'message': data_})


@app.route('/liquidteam_trade', methods=['GET', 'POST'])
def liquidteam_trade():
  print(request.json)
  session_cookie = request.cookies.get('_session')
  decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
  blt_data = mbr_col.document(decoded_claims['email']).collection('trading').document('LiquidTeam_bullets')

  # for i in range(100):
  #  blt_data.update({
  #    str(i+1)+'.status': 'Bought',
  #  })

  if request.json['side'] == 'sell':
    ent = str(int(time.time() * 1000))
    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])

    if onc_blt_data['status'] == 'Sold':
      print('Flood')
      return jsonify({'message': 'bulletfalse'})

    blt_data.update({
      request.json['bullet']+'.status': 'Sold',
      request.json['bullet']+'.ent': ent,
    })
    try:
      cf_ = trd_col.document('LiquidTeam').get().to_dict()[decoded_claims['uid']]['cashflow']
      # cf_ = mbr_col.document(decoded_claims['email']).collection('trading').document('liquidteam').get().to_dict().get('cashflow')

      try:
        sold = float(onc_blt_data['sell']['price'])
      except Exception as e:
        print(e)
        sold = float(0)

      res = requests.get('https://api.liquid.com/products/83')
      data_ = json.loads(res.text)
      bid = data_['market_bid']

      if (sold - bid) > cf_:
        blt_data.update({
          request.json['bullet']+'.status': 'Bought',
        })
        return jsonify({'message': 'rperror'})

      now = int(datetime.datetime.timestamp(datetime.datetime.now())*1000)
      path = '/orders/'
      auth_payload = {
        'path': path,
        'nonce': now,
        'token_id': liquid_id
      }
      signature = jwt.encode(auth_payload, liquid_sc, algorithm='HS256')
      headers = {
        'content-type' : 'application/json',
        'X-Quoine-API-Versioncept': '2',
        'X-Quoine-Auth': signature
      }
      data = {
        "order": {
          "order_type": "market",
          "product_id": 83,
          "side": "sell",
          "quantity": "1"
        }
      }
      ent_ = blt_data.get().to_dict().get(request.json['bullet'])['ent']

      if ent_ != ent:
        print('Flood')
        return jsonify({'message': 'requesterror'})

    except Exception as e:
      print(e)
      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      return jsonify({'message': 'orderfalse'})

    try:
      res = requests.post('https://api.liquid.com' + path, headers=headers, json=data)
      data_ = json.loads(res.text)

      if 'id' in data_:
        price_ = float(data_['price'])
        price_ = float(round(price_ - ((price_/100)*0.3), 3))
        data_['price'] = price_
        blt_data.update({
          request.json['bullet']+'.comment': request.json['comment'],
          request.json['bullet']+'.sell.price': price_,
          request.json['bullet']+'.sell.time': data_['created_at']
        })

        trans =  trt_col.document('liquidteam')
        trans.update({
          data_['id']+'.bullet': request.json['bullet'],
          data_['id']+'.comment': request.json['comment'],
          data_['id']+'.trader': decoded_claims['email']
        })

        if price_ < sold:
          cf_ = cf_ - (sold - price_)
          cf_ = float(round(cf_, 5))
          cf_data = trd_col.document('LiquidTeam')
          cf_data.update({decoded_claims['uid']+'.cashflow': cf_})

        return jsonify({'message': 'tradesuccess', 'data': data_, 'cf': cf_})

      if 'errors' in data_:
        blt_data.update({
          request.json['bullet']+'.status': 'Bought',
        })
        return jsonify({'message': 'orderfalse'})

    except Exception as e:
      print(e)
      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      return jsonify({'message': 'orderfalse'})

  if request.json['side'] == 'buy':
    ent = str(int(time.time() * 1000))
    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])

    if onc_blt_data['status'] == 'Bought':
      print('Flood')
      return jsonify({'message': 'bulletfalse'})

    blt_data.update({
      request.json['bullet']+'.status': 'Bought',
      request.json['bullet']+'.ent': ent,
    })

    try:
      cf_ = trd_col.document('LiquidTeam').get().to_dict()[decoded_claims['uid']]['cashflow']
      # cf_ = mbr_col.document(decoded_claims['email']).collection('trading').document('liquidteam').get().to_dict().get('cashflow')

      try:
        sold = float(onc_blt_data['sell']['price'])
      except Exception as e:
        print(e)
        sold = float(0)

      res = requests.get('https://api.liquid.com/products/83')
      data_ = json.loads(res.text)
      offer = data_['market_ask']

      if offer > sold:
        blt_data.update({
          request.json['bullet']+'.status': 'Sold',
        })
        return jsonify({'message': 'rperror'})

      now = int(datetime.datetime.timestamp(datetime.datetime.now())*1000)
      path = '/orders/'
      auth_payload = {
        'path': path,
        'nonce': now,
        'token_id': liquid_id
      }
      signature = jwt.encode(auth_payload, liquid_sc, algorithm='HS256')

      headers = {
        'content-type' : 'application/json',
        'X-Quoine-API-Versioncept': '2',
        'X-Quoine-Auth': signature
      }

      data = {
        "order": {
          "order_type": "market",
          "product_id": 83,
          "side": "buy",
          "quantity": "1"
        }
      }
      ent_ = blt_data.get().to_dict().get(request.json['bullet'])['ent']

      if ent_ != ent:
        print('Flood')
        return jsonify({'message': 'requesterror'})

    except Exception as e:
      print(e)
      blt_data.update({
        request.json['bullet']+'.status': 'Sold',
      })
      return jsonify({'message': 'orderfalse'})

    try:
      res = requests.post('https://api.liquid.com' + path, headers=headers, json=data)
      data_ = json.loads(res.text)

      if 'id' in data_:
        price_ = float(data_['price'])
        price_ = float(round(price_ + ((price_/100)*0.3), 3))
        data_['price'] = price_
        blt_data.update({
          request.json['bullet']+'.comment': request.json['comment'],
          request.json['bullet']+'.buy.price': price_,
          request.json['bullet']+'.buy.time': data_['created_at']
        })

        trans =  trt_col.document('liquidteam')
        trans.update({
          data_['id']+'.bullet': request.json['bullet'],
          data_['id']+'.comment': request.json['comment'],
          data_['id']+'.trader': decoded_claims['email']
        })

        cf_ = cf_ + (sold - price_)
        cf_ = float(round(cf_, 5))
        cf_data = trd_col.document('LiquidTeam')
        cf_data.update({decoded_claims['uid'] + '.cashflow': cf_})
        return jsonify({'message': 'tradesuccess', 'data': data_, 'cf': cf_})

      if 'errors' in data_:
        blt_data.update({
          request.json['bullet']+'.status': 'Sold',
        })
        return jsonify({'message': 'orderfalse'})

    except Exception as e:
      print(e)
      blt_data.update({
        request.json['bullet']+'.status': 'Sold',
      })
      return jsonify({'message': 'orderfalse'})

      # blt_data = mbr_col.document(decoded_claims['email']).collection('trading').document('xrphunter').collection('bullets').document('data').get().to_dict()

  print('error')
  if request.json['side'] == 'sell':
    blt_data.update({
      request.json['bullet']+'.status': 'Bought',
    })

  if request.json['side'] == 'buy':
    blt_data.update({
      request.json['bullet']+'.status': 'Sold',
    })
  return jsonify({'message': 'error'})


@app.route('/clubfeedxrp_bot_table', methods=['GET', 'POST'])
def clubfeedxrp_bot_table():
  session_cookie = request.cookies.get('_session')
  decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)

  blt_data = mbr_col.document(decoded_claims['email']).collection('trading').document('ClubFeedXRP_bot_bullets')

  if request.json['method'] == 'cancel':
    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])
    return jsonify({'message': 'success', 'sell_pending': onc_blt_data['sell_pending'], 'buy_pending': onc_blt_data['buy_pending']})

  elif request.json['method'] == 'save':
    blt_data.update({
      request.json['bullet']+'.sell_pending': request.json['sell'],
      request.json['bullet']+'.buy_pending': request.json['buy']
    })

    return jsonify({'message': 'success'})


@app.route('/clubfeedxrp_hand_trans', methods=['GET', 'POST'])
def clubfeedxrp_hand_trans():
  ts = int(time.time())

    payload = {
      'ts': ts,
      'sym': 'thb_xrp'
      }

    payload_ = json.dumps(payload)

    signature = hmac.new(config.bitkub_sc.encode(), payload_.encode(), digestmod=hashlib.sha256).hexdigest()

    payload['sig'] = signature
    headers = {'accept': 'application/json', 'content-type': 'application/json', 'x-btk-apikey': config.bitkub_ky}

    url = 'https://api.bitkub.com/api/market/my-order-history'
    res = requests.post(url, json=payload, headers=headers)
    data_ = json.loads(res.text)
    print(json.dumps(data_, indent=2))
    return jsonify({'message': 'trans'})


@app.route('/clubfeedxrp_hand_trade', methods=['GET', 'POST'])
def clubfeedxrp_hand_trade():
  print(request.json)
  session_cookie = request.cookies.get('_session')
  decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)

  blt_data = mbr_col.document(decoded_claims['email']).collection('trading').document('ClubFeedXRP_hand_bullets')

  if request.json['side'] == 'sell':

    ent = str(int(time.time()*1000))

    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])

    if onc_blt_data['status'] == 'Sold':
      print('Flood')
      return jsonify({'message': 'bulletfalse'})

    blt_data.update({
      request.json['bullet']+'.status': 'Sold',
      request.json['bullet']+'.ent': ent,
    })
    cf_ = trd_col.document('ClubFeedXRP_hand').get().to_dict()[decoded_claims['uid']]['cashflow']

    try:
      sold = float(onc_blt_data['sell'])
    except Exception as e:
      print(e)
      sold = float(0)

    try:
      bought = float(onc_blt_data['buy'])
    except Exception as e:
      print(e)
      bought = float(0)

    res = requests.get('https://api.bitkub.com/api/market/bids?sym=thb_xrp&lmt=1')
    data_ = json.loads(res.text)
    bid = data_['result'][0][3]

    if ((sold - bid)*int(onc_blt_data['amount'])) > cf_:
      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      return jsonify({'message': 'rperror'})

    if bid < bought:
      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      return jsonify({'message': 'rperror'})

    ts = int(time.time())

    payload = {
      'ts': ts,
      'sym': 'thb_xrp',
      'amt': onc_blt_data['amount'],
      'rat': bid,
      'typ': 'market'
    }

    payload_ = json.dumps(payload)
    signature = hmac.new(config.bitkub_sc.encode(), payload_.encode(), digestmod=hashlib.sha256).hexdigest()
    payload['sig'] = signature
    headers = {'accept': 'application/json', 'content-type': 'application/json', 'x-btk-apikey': config.bitkub_ky}
    ent_ = blt_data.get().to_dict().get(request.json['bullet'])['ent']

    if ent_ != ent:
      print('Flood')
      return jsonify({'message': 'requesterror'})

    url = 'https://api.bitkub.com/api/market/place-ask'
    res = requests.post(url, json=payload, headers=headers)
    data_ = json.loads(res.text)

    if data_['error'] == 0:

      price_ = float(data_['result']['rat'])
      price_ = float(round((price_ - (price_/100)*0.3), 2))
      data_['result']['rat'] = price_

      blt_data.update({
        request.json['bullet']+'.comment': request.json['comment'],
        request.json['bullet']+'.sell': price_
      })

      trans =  trt_col.document('ClubFeedXRP_hand')
      trans.update({
        str(data_['result']['id'])+'.bullet': request.json['bullet'],
        str(data_['result']['id'])+'.amount': onc_blt_data['amount'],
        str(data_['result']['id'])+'.comment': request.json['comment'],
        str(data_['result']['id'])+'.trader': decoded_claims['email']
      })

      if price_ < sold:
        cf_ = cf_ - ((sold - price_) * int(onc_blt_data['amount']))
        cf_ = float(round(cf_, 2))
        cf_data = trd_col.document('ClubFeedXRP_hand')
        cf_data.update({decoded_claims['uid']+'.cashflow': cf_})

      return jsonify({'message': 'tradesuccess', 'data': data_, 'cf': cf_, 'side': 'sell'})

    else:

      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      print(data_)
      print(payload)
      return jsonify({'message': 'orderfalse'})

  if request.json['side'] == 'buy':
    ent = str(int(time.time()*1000))
    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])

    if onc_blt_data['status'] == 'Bought':
      print('Flood')
      return jsonify({'message': 'bulletfalse'})

    blt_data.update({
      request.json['bullet']+'.status': 'Bought',
      request.json['bullet']+'.ent': ent,
    })

    cf_ = trd_col.document('ClubFeedXRP_hand').get().to_dict()[decoded_claims['uid']]['cashflow']

    try:
      sold = float(onc_blt_data['sell'])
    except Exception as e:
      print(e)
      sold = float(0)

    res = requests.get('https://api.bitkub.com/api/market/asks?sym=thb_xrp&lmt=1')

    data_ = json.loads(res.text)

    offer = data_['result'][0][3]

    if offer > sold:
      blt_data.update({
        request.json['bullet']+'.status': 'Sold',
      })
      return jsonify({'message': 'rperror'})

    ts = int(time.time())

    payload = {
      'ts': ts,
      'sym': 'thb_xrp',
      'amt': onc_blt_data['amount']*offer,
      'rat': offer,
      'typ': 'market'
    }

    payload_ = json.dumps(payload)
    signature = hmac.new(config.bitkub_sc.encode(), payload_.encode(), digestmod=hashlib.sha256).hexdigest()
    payload['sig'] = signature
    headers = {'accept': 'application/json', 'content-type': 'application/json', 'x-btk-apikey': config.bitkub_ky}
    ent_ = blt_data.get().to_dict().get(request.json['bullet'])['ent']

    if ent_ != ent:
      print('Flood')
      return jsonify({'message': 'requesterror'})

    url = 'https://api.bitkub.com/api/market/place-bid'
    res = requests.post(url, json=payload, headers=headers)
    data_ = json.loads(res.text)

    if data_['error'] == 0:
      price_ = float(data_['result']['rat'])
      price_ = float(round((price_ + (price_/100)*0.3), 2))
      data_['result']['rat'] = price_

      blt_data.update({
        request.json['bullet']+'.comment': request.json['comment'],
        request.json['bullet']+'.buy': price_
      })

      trans =  trt_col.document('ClubFeedXRP_hand')
      trans.update({
        str(data_['result']['id'])+'.bullet': request.json['bullet'],
        str(data_['result']['id'])+'.amount': onc_blt_data['amount'],
        str(data_['result']['id'])+'.comment': request.json['comment'],
        str(data_['result']['id'])+'.trader': decoded_claims['email']
      })

      cf_ = cf_ + ((sold - price_)*int(onc_blt_data['amount']))
      cf_ = float(round(cf_, 2))

      cf_data = trd_col.document('ClubFeedXRP_hand')
      cf_data.update({decoded_claims['uid']+'.cashflow': cf_})

      return jsonify({'message': 'tradesuccess', 'data': data_, 'cf': cf_, 'side': 'buy'})

    else:

      blt_data.update({
        request.json['bullet']+'.status': 'Sold',
      })
      return jsonify({'message': 'orderfalse'})

  print('error')
  if request.json['side'] == 'sell':
    blt_data.update({
      request.json['bullet']+'.status': 'Bought',
    })

  if request.json['side'] == 'buy':
    blt_data.update({
      request.json['bullet']+'.status': 'Sold',
    })
  return jsonify({'message': 'error'})


@app.route('/demo_trade', methods=['GET', 'POST'])
def demo_trade():
  print(request.json)
  session_cookie = request.cookies.get('_session')
  decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)

  blt_data = mbr_col.document(decoded_claims['email']).collection('trading').document('DemoTrade_bullets')

  if request.json['side'] == 'sell':
    ent = str(int(time.time()*1000))
    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])

    if onc_blt_data['status'] == 'Sold':
      print('Flood')
      return jsonify({'message': 'bulletfalse'})

    blt_data.update({
      request.json['bullet']+'.status': 'Sold',
      request.json['bullet']+'.ent': ent,
    })

    cf_ = trd_col.document('DemoTrade').get().to_dict()[decoded_claims['uid']]['cashflow']

    try:
      sold = float(onc_blt_data['sell'])
    except Exception as e:
      print(e)
      sold = float(0)

    try:
      bought = float(onc_blt_data['buy'])
    except Exception as e:
      print(e)
      bought = float(0)

    res = requests.get('https://api.bitkub.com/api/market/bids?sym=thb_xrp&lmt=1')

    data_ = json.loads(res.text)

    bid = data_['result'][0][3]

    if ((sold - bid)*int(onc_blt_data['amount'])) > cf_:
      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      return jsonify({'message': 'rperror'})

    if bid < bought:
      blt_data.update({
        request.json['bullet']+'.status': 'Bought',
      })
      return jsonify({'message': 'rperror'})

    # data_ = json.loads(res.text)
    data_ = {
      'error': 0,
      'result': {
        'id': 0,
        'hash': 'AAA',
        'typ': 'market',
        'amt': 2,
        'rat': bid,
        'fee': 0,
        'cre': 0,
        'rec': 0,
        'ts': 0}}

    if data_['error'] == 0:

      price_ = float(data_['result']['rat'])
      price_ = float(round((price_ - (price_/100)*0.3), 2))
      data_['result']['rat'] = price_

      blt_data.update({
        request.json['bullet']+'.comment': request.json['comment'],
        request.json['bullet']+'.sell': price_
      })

      if price_ < sold:
        cf_ = cf_ - ((sold - price_)*int(onc_blt_data['amount']))
        cf_ = float(round(cf_, 2))
        cf_data = trd_col.document('DemoTrade')
        cf_data.update({decoded_claims['uid']+'.cashflow': cf_})

      return jsonify({'message': 'tradesuccess', 'data': data_, 'cf': cf_, 'side': 'sell'})

    else:

      blt_data.update({
        request.json['bullet'] + '.status': 'Bought',
      })
      return jsonify({'message': 'orderfalse'})

  if request.json['side'] == 'buy':

    ent = str(int(time.time() * 1000))

    onc_blt_data = blt_data.get().to_dict().get(request.json['bullet'])

    if onc_blt_data['status'] == 'Bought':
      print('Flood')
      return jsonify({'message': 'bulletfalse'})

    blt_data.update({
      request.json['bullet']+'.status': 'Bought',
      request.json['bullet']+'.ent': ent,
    })

    cf_ = trd_col.document('DemoTrade').get().to_dict()[decoded_claims['uid']]['cashflow']

    try:
      sold = float(onc_blt_data['sell'])
    except Exception as e:
      print(e)
      sold = float(0)

    res = requests.get('https://api.bitkub.com/api/market/asks?sym=thb_xrp&lmt=1')

    data_ = json.loads(res.text)

    offer = data_['result'][0][3]

    if offer > sold:
      blt_data.update({
        request.json['bullet']+'.status': 'Sold',
      })
      return jsonify({'message': 'rperror'})

    # data_ = json.loads(res.text)
    data_ = {
      'error': 0,
      'result': {
        'id': 0,
        'hash': 'AAA',
        'typ': 'market',
        'amt': 2,
        'rat': offer,
        'fee': 0,
        'cre': 0,
        'rec': 0,
        'ts': 0}}

    if data_['error'] == 0:

      price_ = float(data_['result']['rat'])
      price_ = float(round((price_ + (price_/100)*0.3), 2))
      data_['result']['rat'] = price_

      blt_data.update({
        request.json['bullet']+'.comment': request.json['comment'],
        request.json['bullet']+'.buy': price_
      })

      cf_ = cf_ + ((sold - price_)*int(onc_blt_data['amount']))
      cf_ = float(round(cf_, 2))
      cf_data = trd_col.document('DemoTrade')
      cf_data.update({decoded_claims['uid']+'.cashflow': cf_})

      return jsonify({'message': 'tradesuccess', 'data': data_, 'cf': cf_, 'side': 'buy'})

    else:

      blt_data.update({
        request.json['bullet']+'.status': 'Sold',
      })
      return jsonify({'message': 'orderfalse'})

  print('error')
  if request.json['side'] == 'sell':
    blt_data.update({
      request.json['bullet']+'.status': 'Bought',
    })

  if request.json['side'] == 'buy':
    blt_data.update({
      request.json['bullet']+'.status': 'Sold',
    })
  return jsonify({'message': 'error'})


@app.route('/sign', methods=['GET', 'POST'])
def sign():
  if '_session' in request.cookies:

    response = jsonify({'status': 'signout'})
    response.set_cookie('_session', '', expires=0, httponly=True, secure=True)

    return response

  else:

    return jsonify({'status': 'signin'})


@app.route('/', defaults={'dinamic': ''}, methods=['GET', 'POST'])
@app.route('/<dinamic>', methods=['GET', 'POST'])
def index(dinamic):
  if '_session' not in request.cookies:
    print('Return login page.')
    return redirect('/signin')

  else:

    try:
      session_cookie = request.cookies.get('_session')
      decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
      mbr_email = decoded_claims['email']
      mbr_data = mbr_col.document(mbr_email).get().to_dict()

      # ---------------------------------
      facebook_rm = db.collection('facebook_remove').document(mbr_email).get()
      if facebook_rm.exists:
        trading_col = db.collection('trading')
        fb_uid = facebook_rm.to_dict()['uid']
        members_uid_ = trading_col.document('LiquidTeam').get().to_dict()

        if fb_uid in members_uid_:
          trading_col.document('LiquidTeam').update({
            decoded_claims['uid']: members_uid_[fb_uid]
          })
          trading_col.document('LiquidTeam').update({
            fb_uid: firestore.DELETE_FIELD
          })

        members_uid_ = trading_col.document('ClubFeedXRP_hand').get().to_dict()

        if fb_uid in members_uid_:
          trading_col.document('ClubFeedXRP_hand').update({
            decoded_claims['uid']: members_uid_[fb_uid]
          })
          trading_col.document('ClubFeedXRP_hand').update({
            fb_uid: firestore.DELETE_FIELD
          })

        db.collection('facebook_remove').document(mbr_email).delete()

      # ---------------------------------

      if dinamic == '':
        return render_template('index.html', title = _title, dinamic = dinamic, mbr_email = mbr_email, mbr_data = mbr_data)

      elif dinamic == 'LiquidTeam':
        try:
          trd_data = trd_col.document(dinamic).get().to_dict()[decoded_claims['uid']]
          trading = mbr_col.document(mbr_email).collection('trading').document(dinamic+'_bullets').get().to_dict()
          trading = dict({int(k):v for k,v in trading.items()})
          trading = sorted(trading.items())
          trading = dict({str(k):v for k,v in trading})

        except Exception as e:
          print(e)
          trading = {}
        return render_template('index.html', title = _title, dinamic = dinamic, trading = trading, mbr_email = mbr_email, mbr_data = mbr_data, trd_data = trd_data)


      elif dinamic == 'DemoTrade':
        try:
          trd_data = trd_col.document(dinamic).get().to_dict()[decoded_claims['uid']]
          trading = mbr_col.document(mbr_email).collection('trading').document(dinamic+'_bullets').get().to_dict()
          trading = dict({int(k):v for k,v in trading.items()})
          trading = sorted(trading.items())
          trading = dict({str(k): v for k, v in trading})
        except Exception as e:
          print(e)
          trading = {}
          if mbr_data['ident'] == 99:
            trd_data = {'email': mbr_email, 'ident': 99}
        return render_template('index.html', title = _title, dinamic = dinamic, trading = trading, mbr_email = mbr_email, mbr_data = mbr_data, trd_data = trd_data)


      elif dinamic == 'ClubFeedXRP_hand':
        try:
          trd_data = trd_col.document(dinamic).get().to_dict()[decoded_claims['uid']]
          trading = mbr_col.document(mbr_email).collection('trading').document(dinamic+'_bullets').get().to_dict()
          trading = dict({int(k):v for k,v in trading.items()})
          trading = sorted(trading.items())
          trading = dict({str(k): v for k, v in trading})
        except Exception as e:
          print(e)
          trading = {}
          if mbr_data['ident'] == 99:
            trd_data = {'email': mbr_email, 'ident': 99}
        return render_template('index.html', title = _title, dinamic = dinamic, trading = trading, mbr_email = mbr_email, mbr_data = mbr_data, trd_data = trd_data)

      elif dinamic == 'ClubFeedXRP_bot':
        try:
          trd_data = trd_col.document(dinamic).get().to_dict()[decoded_claims['uid']]
          trading = mbr_col.document(mbr_email).collection('trading').document(dinamic+'_bullets').get().to_dict()
          trading = dict({int(k):v for k,v in trading.items()})
          trading = sorted(trading.items())
          trading = dict({str(k): v for k, v in trading})
        except Exception as e:
          print(e)
          trading = {}
          if mbr_data['ident'] == 99:
            trd_data = {'email': mbr_email, 'ident': 99}
        return render_template('index.html', title = _title, dinamic = dinamic, trading = trading, mbr_email = mbr_email, mbr_data = mbr_data, trd_data = trd_data)


      else:
        return redirect('/')

    except Exception as e:
      print(e)
      return render_template('index.html')


@app.route('/test', methods=['GET', 'POST'])
def test():
  mbr_col = db.collection('members')
  trd_doc = db.collection('trading').document('LiquidTeam')
  mbr_data = dict((i.id, i.to_dict()) for i in mbr_col.stream())

  for email in mbr_data.keys():
    mbr_col.document(email).update({
        'trading': ['LiquidTeam']
    })

  return 'test'

  mbr_col = db.collection('members')
  trd_doc = db.collection('trading').document('LiquidTeam')
  mbr_data = dict((i.id, i.to_dict()) for i in mbr_col.stream())

  for email in mbr_data.keys():
    copy = mbr_col.document(email).collection('trading').document('liquidteam').collection('bullets').document('data')
    past = mbr_col.document(email).collection('trading').document('LiquidTeam_bullets')

    if email != 'phatsin.lk@gmail.com':
      past.set(copy.get().to_dict())

    copy = mbr_col.document(email).collection('trading').document('liquidteam')
    copx = mbr_col.document(email)

    if email != 'phatsin.lk@gmail.com':
      try:
        trd_doc.update({
          auth.get_user_by_email(email).uid: {'email': email, 'ident': copx.get().to_dict()['ident'], 'cashflow': copy.get().to_dict()['cashflow']}
        })
      except Exception as e:
        print(e)
        trd_doc.update({
          auth.get_user_by_email(email).uid: {'email': email, 'ident': copx.get().to_dict()['ident']}
        })

  return 'test'

  mbr_col = db.collection('members')
  trd_doc = db.collection('trading').document('liquidteam')
  mbr_data = dict((i.id, i.to_dict()) for i in mbr_col.stream())
  for email in mbr_data.keys():
    copy = mbr_col.document(email).collection('trading').document('liquidteam_bullets')
    past = mbr_col.document(email).collection('trading').document('LiquidTeam_bullets')

    if email == 'phatsin.lk@gmail.com':
      past.set(copy.get().to_dict())

  return 'test'
  session_cookie = request.cookies.get('_session')
  decoded_claims = auth.verify_session_cookie(session_cookie, check_revoked=True)
  user = auth.get_user_by_email(decoded_claims['email'])
  print('Successfully fetched user data: {0}'.format(user.uid))
  # cf_data = trd_col.document('liquidteam')
  # test = {decoded_claims['uid']+".cashflow": 3.428}
  # cf_data.update(test)

  return 'test'

  mbr_col = db.collection('members')
  mbr_data = dict((i.id, i.to_dict()) for i in mbr_col.stream())
  for email in mbr_data.keys():
    copy = mbr_col.document(email).collection('trading').document('liquidteam')
    past = mbr_col.document(email)

    if email == 'phatsin.lk@gmail.com':
      print(copy.get().to_dict())

      past.update({
        'trading.liquidteam.cashflow': copy.get().to_dict()['cashflow'],
      })

  return 'test'

  if request.MOBILE:
    return 'Yes'
  else:
    return 'No'

  db_col = db.collection('transactions')
  _copy = 'xrphunter'
  _paste = 'liquidteam'
  copy = db_col.document(_copy)
  paste = db_col.document(_paste)
  paste.set(
    copy.get().to_dict()
  )

  return 'test'
  mbr_col = db.collection('members')
  mbr_data = dict((i.id, i.to_dict()) for i in mbr_col.stream())

  print(mbr_data.keys())
  for email in mbr_data.keys():
    _copy = 'xrphunter'
    _paste = 'liquidteam'

    copy = mbr_col.document(email).collection('trading').document(_copy)
    paste = mbr_col.document(email).collection('trading').document(_paste)
    paste.set(
      copy.get().to_dict()
    )

  for email in mbr_data.keys():
    copy = mbr_col.document(email).collection('trading').document(_copy).collection('bullets').document('data')
    paste = mbr_col.document(email).collection('trading').document(_paste).collection('bullets').document('data')
    paste.set(
      copy.get().to_dict()
    )

  return 'test'


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080, debug=True)
