import base64
import hashlib
import hmac
import simplejson
import time

GC_SECRET = '123456'
GC_PUBLIC = 'abcdef'

def get_graphcomment_sso(user):
    # create a JSON packet of our data attributes
    data = simplejson.dumps({
        'id': user['id'],# required unique
        'username': user['username'],# required unique
        'email': user['email'],# required unique
        'language': user['language'],#(optionnal) default value : en (codes ISO 639-1)
        'bio': user['bio'],#(optionnal) description
        'picture' : user['picture']#(optionnal) full url only
    })
    # encode the data to base64
    message = base64.b64encode(data)
    # generate a timestamp for signing the message
    timestamp = int(time.time())
    # generate our hmac signature
    sig = hmac.HMAC(GC_SECRET, '%s %s' % (message, timestamp), hashlib.sha1).hexdigest()

    # return a script tag to insert the sso message
    return """<script type="text/javascript">
    var gc_config = function() {
        this.page.auth = "%(message)s %(sig)s %(timestamp)s";
        this.page.pubKey = "%(pub_key)s";
    }
    </script>""" % dict(
        message=message,
        timestamp=timestamp,
        sig=sig,
        pub_key=GC_PUBLIC,
    )