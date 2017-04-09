from roundup.cgi.actions import Action
from roundup.cgi.exceptions import *
from roundup import date
from roundup import password

class MyAction(Action):
    def handle(self):
        ''' Perform some action. No return value is required.
        '''
        db = self.client.db
        if not self.client.session_api.get('oauth_token'):
            print 'oath is %s' % (self.client.session_api.get('oauth_token'))
        else:
            print 'Do stuff if '     
            print 'oath is %s' % (self.client.session_api.get('oauth_token'))
        # print db.config.ext['QA_RECIPIENTS']
        # print type(self.db.config.ext['DATAUG_OAUTH2_SCOPE'].split(","))
        # print self.db.config.ext['DATAUG_OAUTH2_CLIENT_ID']
        # print self.db.config.ext['DATAUG_OAUTH2_AUTHORIZATION_BASE_URL']
        print db.user.list()
        today = date.Date()
        props = {'username':'token' + str(today)}
        passwd = password.generatePassword(100)
        # print str(today)
        print props 
        userid = db.user.create(**props)
        self.db.user.set(userid,
                roles=self.db.config['NEW_WEB_USER_ROLES'])
        self.db.user.set(userid,
                password=password.Password(passwd))        
        db.commit()
        print "New password%s " % (password.generatePassword(100))
        print "%s?@action=login1" % (self.client.base)
        print "db classname %s type %s" % (db.user.__class__.__name__, type(db.user))
        self.client.add_ok_message(self._('You are loggedsxds out'))




def init(instance):
    instance.registerAction('myaction', MyAction)

