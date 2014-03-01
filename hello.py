import os
import base64
import re
import uuid
import json
import datetime
import hmac
import sha
import urllib
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.debug = True

def s3_upload_policy_document():
    """Generate policy based on
    http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    """
    b64policy = base64.b64encode(
      json.dumps({
        'expiration': (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        'conditions': [
          { 'bucket': os.getenv('S3_BUCKET') },
          { 'acl': 'public-read' },
          ["starts-with", "$key", "uploads/"],
          { 'success_action_status': '201' }
        ]
      })
    )
    return unicode(b64policy)


def s3_upload_signature():
    """Generate signature based on
    http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
    """
    # hashed = hmac.new(os.getenv('AWS_SECRET_KEY_ID'), s3_upload_policy_document(), sha1).digest()
    # app.logger.debug(s3_upload_policy_document())
    # app.logger.debug(base64.b64decode(s3_upload_policy_document()))
    # app.logger.debug(os.getenv('AWS_SECRET_KEY_ID'))
    # signature = base64.b64encode(hmac.new(os.getenv('AWS_SECRET_KEY_ID'), s3_upload_policy_document(), sha).digest())
    signature = base64.encodestring(hmac.new(os.getenv('AWS_SECRET_KEY_ID'), s3_upload_policy_document(), sha).digest()).strip()
    return signature


@app.route("/")
def hello():
    return render_template('index.html')

@app.route("/signed_urls")
def signed_urls():
    title = request.args.get('title')
    payload = {
      'policy': s3_upload_policy_document(),
      'signature': s3_upload_signature(),
      'key': "uploads/%s/%s" % (str(uuid.uuid4()), title),
      'success_action_redirect': "/"
    }

    return jsonify(payload)

if __name__ == "__main__":
    app.run()
