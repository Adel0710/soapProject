from django.conf import settings
from datetime import timedelta
import datetime
import jwt

def generate_access_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.now(datetime.UTC) + timedelta(days=1, minutes=0),
        'iat': datetime.datetime.now(datetime.UTC),
    }

    access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return access_token
