from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.hashers import make_password, check_password
from .utils import generate_access_token,get_user_from_token
from .models import Users, Products
from .serializers import UsersSerializer, ProductsSerializer
import jwt
from django.conf import settings
from django.db import connection
import logging
import json

def index(request):
    return HttpResponse("Bonjour")

@csrf_exempt
def create_user_view(request):
    if request.method == 'GET':
        User = get_user_model()
        users = User.objects.all()
        serializer = UsersSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    elif request.method == 'POST':
        data = json.loads(request.body)
        serializer = UsersSerializer(data=data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                return JsonResponse({"message": "User successfully created"}, status=201)
            except Exception as e:
                return JsonResponse({"error": str(e)}, status=400)
        else:
            return JsonResponse({"errors": serializer.errors}, status=400)
        
logger = logging.getLogger(__name__)

@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            logger.debug(f"Login attempt with email: {email}")

            if not email or not password:
                logger.warning("Email or password not provided")
                return JsonResponse({'error': 'Email and password are required'}, status=400)

            with connection.cursor() as cursor:
                cursor.execute("SELECT id, password FROM users WHERE email=%s", [email])
                user_data = cursor.fetchone()

                if user_data:
                    user_id, hashed_password = user_data
                    if check_password(password, hashed_password):
                        access_token = generate_access_token(user_id).decode('utf-8')  # Decode the token
                        logger.debug(f"Access token generated for user_id: {user_id}")
                        response = JsonResponse({'token': access_token})
                        response.set_cookie('access', access_token, httponly=True, secure=True)
                        return response
                    else:
                        logger.warning(f"Invalid credentials for email: {email}")
                        return JsonResponse({'error': 'Invalid credentials'}, status=400)
                else:
                    logger.warning(f"User not found for email: {email}")
                    return JsonResponse({'error': 'Invalid credentials'}, status=400)

        except json.JSONDecodeError:
            logger.error("Invalid JSON provided")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return JsonResponse({'error': 'An error occurred'}, status=500)
    else:
        logger.warning("Invalid request method")
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def read_users_view(request):
    user = get_user_from_token(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    if not user.isAdmin:
        return JsonResponse({'error': 'Forbidden'}, status=403)

    users = Users.objects.all()
    serializer = UsersSerializer(users, many=True)
    return JsonResponse(serializer.data, safe=False)


@csrf_exempt
def update_user_view(request, id):
    user = get_user_from_token(request)
    if not user or not user.isAdmin:
        return JsonResponse({'error': 'Unauthorized or Forbidden'}, status=401)

    if request.method == 'PUT':
        data = json.loads(request.body)
        firstname = data.get('firstname')
        lastname = data.get('lastname')
        email = data.get('email')
        password = make_password(data.get('password'))
        try:
            user_to_update = Users.objects.get(id=id)
            user_to_update.lastname = lastname
            user_to_update.firstname = firstname
            user_to_update.email = email
            user_to_update.password = password
            user_to_update.save()
            return JsonResponse({'message': 'User updated successfully'})
        except Users.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def delete_user_view(request, id):
    user = get_user_from_token(request)
    if not user or not user.isAdmin:
        return JsonResponse({'error': 'Unauthorized or Forbidden'}, status=401)

    if request.method == 'DELETE':
        try:
            user_to_delete = Users.objects.get(id=id)
            user_to_delete.delete()
            return JsonResponse({'message': 'User deleted successfully'})
        except Users.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def create_product_view(request):
    user = get_user_from_token(request)
    if not user or not user.isAdmin:
        return JsonResponse({'error': 'Unauthorized or Forbidden'}, status=401)

    if request.method == 'POST':
        data = json.loads(request.body)
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        try:
            product = Products.objects.create(name=name, description=description, price=price)
            product.save()
            return JsonResponse({'message': 'Product created successfully'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def read_product_view(request):
    user = get_user_from_token(request)
    if not user:
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    products = Products.objects.all()
    serializer = ProductsSerializer(products, many=True)
    return JsonResponse(serializer.data, safe=False)

@csrf_exempt
def update_product_view(request, id):
    user = get_user_from_token(request)
    if not user or not user.isAdmin:
        return JsonResponse({'error': 'Unauthorized or Forbidden'}, status=401)

    if request.method == 'PUT':
        data = json.loads(request.body)
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        try:
            product = Products.objects.get(id=id)
            product.name = name
            product.description = description
            product.price = price
            product.save()
            return JsonResponse({'message': 'Product updated successfully'})
        except Products.DoesNotExist:
            return JsonResponse({'error': 'Product not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def delete_product_view(request, id):
    user = get_user_from_token(request)
    if not user or not user.isAdmin:
        return JsonResponse({'error': 'Unauthorized or Forbidden'}, status=401)

    if request.method == 'DELETE':
        try:
            product = Products.objects.get(id=id)
            product.delete()
            return JsonResponse({'message': 'Product deleted successfully'})
        except Products.DoesNotExist:
            return JsonResponse({'error': 'Product not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)