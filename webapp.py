from flask import Flask, redirect, url_for, session, request, jsonify
from flask_oauthlib.client import OAuth
from flask import render_template, flash, Markup

from github import Github
import pprint
import os
import sys
import traceback

class GithubOAuthVarsNotDefined(Exception):
    '''raise this if the necessary env variables are not defined '''
if os.getenv('GITHUB_CLIENT_ID') == None or \
        os.getenv('GITHUB_CLIENT_SECRET') == None or \
        os.getenv('APP_SECRET_KEY') == None or \
        os.getenv('GITHUB_ORG') == NOne:
            raise GithubOAuthVarsNotDefined('''
                Please define environment variables:
                    GITHUB_CLIENT_ID
                    GITHUB_CLIENT_SECRET
                    GITHUB_ORG
                    APP_SECRET_KEY
                ''')
app = Flash(__name__)
app.debug = False
app.secret_key = os.environ['APP_SECRET_KEY']
oauth = OAuth(app)

github = oauth.remote_app(
        'github',
        consumer_key=os.environ['GITHUB_CLIENT_ID'],
        consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],
        request_token_params={'scope': 'read:org'},
        base_url='https://api.github.com/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize'
)

@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')

@app.context_processor
def inject_logged_in():
    return dict(logged_in=('github_token' in session))

@app.context_processor
def inject_github_org():
    return dict(github_org=os.getenv('GITHUB_ORG'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='https'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You were logged out')
    return redirect(url_for('home'))

@app.route('/login/authorized')
def authorized():
    resp = github.authorized_response()

    if resp is None:
        session.clear()
        login_error_message = 'Access denied: reason=%s error = %s full = %s' % (request.args['error'], request.args['error_description'], pprint.pformat(request.args))
        flash(login_error_message, 'error')
        return redirect(url_for('home'))
    try:
        session['github_token'] = (resp['access_token'], '')
        session['user_data'] = github.get('user').data
        github_userid = session['user_data']['login']
        org_name = os.getenv('GITHUB_ORG')
    except Exception as e:
        session.clear()
        message = 'Unable to login: ' + str(type(e)) + str(e)
        flash(message, 'error')
        return redirect(url_for('home'))
    try:
        g = Github(resp['access_token'])
        org = g.get_organization(org_name)
        named_user = g.get_user(github_userid)
        isMember = org.has_in_members(named_user)
    except Exception as e:
        message = 'Unable to connect to Github with accessToken: ' + resp['access_token'] + 'exception info: ' + str(type(e)) + str(e)
        session.clear()
        flash(message, 'error')
        return redirect(url_for('home'))

    if not isMember:
        session.clear()
        message = 'Unable to login: ' + github_userid + ' is not a member of ' + org_name + \
                '</p><p><a href="https://github.com/logout" target="_blank_">Logout of github as user:  ' + github_userid + \
                '</a></p>'
        flash(Markup(message), 'error')
    else:
        flash("You were successfully logged in")

    return redirect(url_for('home'))

@app.route('/ctof')
def render_ctof():
    return render_template('ctof.html')

@app.route('/ftoc')
def render_ftoc():
    if 'user_data' in session:
        user_data_pprint = pprint.pformat(session['user_data'])
    else:
        user_data_pprint = '';
    return render_template('ftoc.html')

@app.route('/mtokm')
def render_mtokm():
    return render_template('mtokm.html')


@app.route('/ftoc_result')
def render_ftoc_result():
    try:
        ftemp_result = float(request.args['fTemp'])
        ctemp_result = ftoc(ftemp_result)
        return render_template('ftoc_result.html', fTemp = ftemp_result, cTemp = ctemp_result)
    except ValueError:
        return "Sorry: something went wrong."

@app.route('/ctof_result')
def render_ctof_result():
    try:
        ctemp_result = float(request.args['cTemp'])
        ftemp_result = ctof(ctemp_result)
        return render_template('ctof_result.html', cTemp = ctemp_result, fTemp = ftemp_result)
    except ValueError:
        return "Sorry: something went wrong."

@app.route('/mtokm_result')
def render_mtokm_result():
    try:
        mdist_result = float(request.args['mDist'])
        kmdist_result = mtokm(mdist_result)
        return render_template('mtokm_result.html', kmDist = kmdist_result, mDist = mdist_result)
    except ValueError:
        return "Sorry: something went wrong."

def ftoc(ftemp):
    return (ftemp-32.0)*(5.0/9.0)

def ctof(ctemp):
    return (9.0/5.0*ctemp)+32.0

def mtokm(mdist):
    return (1.61*mdist)

if __name__ == "__main__":
    app.run(debug = True)

