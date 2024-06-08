# ap/middleware.py

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
import jwt

class JWTAuthenticationMiddleware(MiddlewareMixin):

    def process_request(self, request):
        token = request.headers.get('Authorization')
        if token:
            try:
                token = token.split(' ')[1]
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
                user_id = payload['user_id']
                User = get_user_model()
                user = User.objects.get(id=user_id)
                request.user = user
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
                request.user = None
        else:
            request.user = None
