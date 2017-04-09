from roundup import date
from requests_oauthlib import OAuth2Session

def totalTimeSpent(times):
    ''' Call me with a list of timelog items (which have an
        Interval "period" property)
    '''
    total = date.Interval('0d')
    for time in times:
        total += time.period._value
    return total

def init(instance):
    instance.registerUtil('totalTimeSpent', totalTimeSpent)
