from roundup.exceptions import Reject

def print_message(db, cl, nodeid, newvalues):
    #if newvalues['type'] == 'text/html':
    print 'emana yange'

def init(db):
    #db.file.audit('create', reject_html)
    db.msg.audit('create', print_message)
