from roundup.cgi.actions import Action
from requests_oauthlib import OAuth2Session
from roundup.cgi.exceptions import *
from urlparse import urlparse
import json


import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'



class DataugLogin(Action):
    def handle(self):
        ''' Perform some action. No return value is required.
        '''
        # check if variable exists in session
        #
        if not self.client.session_api.get('oauth_token'):
            print 'oath is %s' % (self.client.session_api.get('oauth_token'))
            self.client.user=self.startLogin()

        try:
            # self.verifyLogin(self.client.user, password)
            self.verifyLogin()
        except exceptions.LoginError, err:
            self.client.make_user_anonymous()
            for arg in err.args:
                self.client.add_error_message(arg)
            return        

        print 'name is %s and id %s' % (self.client.user, self.client.userid )   
        self.client.opendb(self.client.user)    

        self.client.session_api.set(user=self.client.user)
        if 'remember' in self.form:
            self.client.session_api.update(set_cookie=True, expire=24*3600*365)            

 



    

    def verifyLogin(self):
        """Fetching a protected resource using an OAuth 2 token.
        """
        client_id = self.db.config.ext['OAUTH2_CLIENT_ID']
        profile = self.db.config.ext['OAUTH2_PROFILE']

        oauth_token = self.client.session_api.get('oauth_token')
        dataug = OAuth2Session(client_id, token=oauth_token)

        # hacky way to force the token to be sent in query.
        # Default way to to send it in header
        dataug._client.default_token_placement = 'query'

        remote_user = dataug.get(profile).json()

        try:
            userid = self.db.user.lookup(remote_user['login'])
        except KeyError:
            # create user
            props = {'username':remote_user['login']}
            userid = self.db.user.create(**props)
            self.db.user.set(userid,
                    roles=self.db.config['NEW_WEB_USER_ROLES'])
            self.db.user.set(userid,
                    address=remote_user['email'])  
            passwd = password.generatePassword(100)
            self.db.user.set(userid,
                    password=password.Password(passwd))                              
            self.db.commit() 
        except:              
            raise exceptions.LoginError(self._('Invalid login'))

        # print type(myresponse)
        self.client.userid = userid
        # print 'My response: %s', myresponse
        self.client.user =  self.db.user.get(self.client.userid, 'username')  

        if not self.hasPermission("Web Access"):
            raise exceptions.LoginError(self._(
                "You do not have permission to login"))                 

    def startLogin(self):
        ''' Start the process of aquiring token. No return value is required.
        '''        
        client_id = self.db.config.ext['OAUTH2_CLIENT_ID']
        scope = self.db.config.ext['OAUTH2_SCOPE'].split(",")
        authorization_base_url = self.db.config.ext['OAUTH2_AUTHORIZATION_BASE_URL']
        redirect_uri = self.db.config.ext['OAUTH2_REDIRECT_URI']

        dataug = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)
        authorization_url, state = dataug.authorization_url(authorization_base_url)
        self.client.session_api.set(oauth_state=state)

        raise Redirect, authorization_url        

class DataugCallback(Action):
    def handle(self):
        ''' Perform some action. No return value is required.
        '''

        client_id = self.db.config.ext['OAUTH2_CLIENT_ID']
        #scope = self.db.config.ext['DATAUG_OAUTH2_SCOPE']
        token_url = self.db.config.ext['OAUTH2_TOKEN_URL']
        client_secret = self.db.config.ext['OAUTH2_CLIENT_SECRET']
        request_url = self.get_request_url()

        # dataug = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)
        # authorization_url, state = dataug.authorization_url(authorization_base_url)
        state = self.client.session_api.get('oauth_state')
        dataug = OAuth2Session(client_id, state=state)
        token = dataug.fetch_token(token_url, client_secret=client_secret,
                                   authorization_response=request_url)     
        self.client.session_api.set(oauth_token=token)                             
        
        #print '==========================================================='
        # print "cleint id %s \ntoken_url %s"  % (client_id, token_url)
        # print "cleint secret %s \n request_url %s" % (client_secret, request_url)
        #print "token %s\n" % (token)        
        # print authorization_url
        # print token
        # print urlparse(self.client.base)
        # print self.get_request_path()
        #print '============================================================'

        login_url = "%s?@action=login" % (self.client.base)

        raise Redirect, login_url
      
    def get_request_url(self):
        url = urlparse(self.client.base)

        # print urlparse() 
        return "%s://%s%s" % (url.scheme, url.netloc, self.client.request.path)

def init(instance):
    instance.registerAction('login', DataugLogin)
    instance.registerAction('callback', DataugCallback)    
