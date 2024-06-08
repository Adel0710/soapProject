from django.conf import settings
from datetime import datetime, timedelta
import jwt

def generate_access_token(user_id):
    expiration_time = datetime.utcnow() + timedelta(days=1)  
    payload = {
        'user_id': user_id,
        'exp': expiration_time,
        'iat': datetime.utcnow(),  
        'token_type': 'access'
    }
    print("Playload:",payload)
    access_token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    print(access_token)
    return access_token.decode('utf-8')


def validate_access_token(token):
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        expiration = payload['exp']

        if expiration < datetime.utcnow():
            raise Exception("Jeton d'accès expiré")

        return user_id
    except jwt.ExpiredSignatureError:
        raise Exception("Jeton d'accès expiré")
    except jwt.InvalidTokenError:
        raise Exception("Jeton d'accès non valide")
    except KeyError:
        raise Exception("Jeton d'accès malformé")
