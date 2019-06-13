import flask
from flask import Flask
from flask import (abort, flash, redirect, render_template, request, session, url_for)
import google.oauth2.credentials
from google.oauth2.id_token import verify_oauth2_token
import google_auth_oauthlib.flow
from google.auth.transport import requests
from decorators import authenticated
import requests as REST
import uuid, json


from threading import Thread, Lock

SESSION_COOKIE_SECURE = True
app = Flask(__name__)


@app.route("/")
def base():
    if session.get("is_authenticated"):
        return redirect(url_for('home'))
    else:
        return redirect(url_for('home_unauth'))

@app.route("/home_unauth")
def home_unauth():
    if session.get("is_authenticated"):
        return redirect(url_for('home'))
    else:
        return render_template("home.jinja2")

@app.route('/login', methods=['GET'])
def login():
    """Send the user to Globus Auth."""
    return redirect(url_for('authcallback'))

@app.route('/authcallback', methods=['GET'])
def authcallback():
    if 'error' in request.args:
        flash("You could not be logged into the application: " +
              request.args.get('error_description', request.args['error']))
        return flask.redirect(url_for(''))
    if 'code' not in request.args:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', "https://www.googleapis.com/auth/userinfo.profile"])
        flow.redirect_uri = flask.url_for('authcallback', _external=True)
        authorization_url, state = flow.authorization_url(
            access_type='offline', include_granted_scopes='true')
        flask.session['state'] = state
        return flask.redirect(authorization_url)
    else:
        code = request.args.get('code')
        state = flask.session['state']
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            'client_secret.json',
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', "https://www.googleapis.com/auth/userinfo.profile"],
            state=state)
        flow.redirect_uri = flask.url_for('authcallback', _external=True)
        authorization_response = flask.request.url
        flow.fetch_token(authorization_response=authorization_response)
        auth_sess = flow.authorized_session()
        id_token = verify_oauth2_token(auth_sess.credentials.id_token, requests.Request())

        """
        EXAMPLE VERIFICATION
        data = json.load(open("world_data.json"))
        if id_token["email"] in data["server_data"]["users"]:
            session.update(id_token = id_token, is_authenticated=True, email=id_token["email"], user_name=id_token["name"])
            return flask.redirect(flask.url_for('home'))
        else:
            session.update(id_token = id_token, is_authenticated=False, email=id_token["email"], user_name=id_token["name"])
            return flask.redirect(flask.url_for('logout'))
        """

        session.update(id_token = id_token, is_authenticated=True, email=id_token["email"], user_name=id_token["name"])
        return flask.redirect(flask.url_for('home'))



@app.route('/logout', methods=['GET'])
@authenticated
def logout():
    revoke = REST.post('https://accounts.google.com/o/oauth2/revoke',
        params={'id_token': session.get("id_token")},
        headers = {'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return "Something Failed, please go <a href="+redirect(url_for('home_unauth'))+">back</a> :(" 

    session.clear()
    return redirect(url_for('home_unauth'))

@app.route('/home', methods=['GET', 'POST'])
@authenticated
def home():
    if request.method == 'GET':
        return render_template("home.jinja2")
    else:
        for key, value in request.form.to_dict().items():
            if value == "button_id":
                return redirect("https://www.google.com")
            else:
                return redirect(url_for('home'))


if __name__ == "__main__":
    app.secret_key = str(uuid.uuid4())
    app.run(port="8080", debug=True, ssl_context='adhoc')
