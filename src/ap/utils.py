from datetime import datetime
import jwt
from django.conf import settings
from .models import Users

def generate_access_token(user_id):
    expiration_time = datetime.utcnow() + settings.JWT_ACCESS_TOKEN_EXPIRES
    payload = {
        'user_id': user_id,
        'exp': expiration_time,
        'iat': datetime.utcnow(),
        'token_type': 'access'
    }
    access_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return access_token

def validate_access_token(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")

def get_user_from_token(request):
    token = request.headers.get('Authorization')
    if token:
        try:
            token = token.split(' ')[1]
            user_id = validate_access_token(token)
            user = Users.objects.get(id=user_id)
            return user
        except Exception as e:
            return None
    return None
