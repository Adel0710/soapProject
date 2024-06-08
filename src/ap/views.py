from rest_framework import viewsets
import logging
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from django.shortcuts import redirect
from django.contrib.auth import authenticate
from django.http import HttpResponse, JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import connection
from django.contrib.auth import get_user_model
from .utils import generate_access_token
from .models import Users, Products
from .serializers import UsersSerializer, ProductsSerializer, LoginSerializer
from django.conf import settings
from django.contrib.auth.hashers import make_password, check_password
import json 
import jwt

def index(request):
    return HttpResponse("Bonjour")


class CreateUserView(APIView):
    permission_classes = [AllowAny]

    @csrf_exempt
    def get(self, request, *args, **kwargs):
        User = get_user_model()
        users = User.objects.all()
        serializer = UsersSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False)

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        serializer = UsersSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                return JsonResponse({"message": "User successfully created"}, status=201)
            except Exception as e:
                logging.error(f"Error creating user: {e}")
                return JsonResponse({"error": str(e)}, status=400)
        else:
            return JsonResponse({"errors": serializer.errors}, status=400)



class ReadUsersView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.headers
        print("tutu" + token)
        print(token)
        if not token:
            return Response({'error': 'No access token found in session'}, status=401)

        try:
            decode_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            print(decode_token)
            user_id = decode_token.get(user_id)
        
            if not user_id:
                return Response({'error': 'User ID not found in token'}, status=401)

            if not request.user.is_authenticated or not request.user.is_staff:
                return Response({'error': 'User is not authenticated or not an admin'}, status=403)

            users = Users.objects.all()
            serializer = UsersSerializer(users, many=True)
            return Response(serializer.data)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Expired access token'}, status=401)
        except jwt.InvalidTokenError:
            return Response({'error': 'Invalid access token'}, status=401)

    


class UpdateUserView(APIView):
    def put(self, request, id):
        firstname = request.data.get('firstname')
        lastname = request.data.get('lastname')
        email = request.data.get('email')
        password = make_password(request.data.get('password'))

        try:
            user = Users.objects.get(id=id)
            user.lastname = lastname
            user.firstname = firstname
            user.email = email
            user.password = password
            user.save()
            return JsonResponse({'message': 'User updated successfully'})
        except Users.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


class DeleteUserView(APIView):
    def delete(self, request, id):
        try:
            user = Users.objects.get(id=id)
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'})
        except Users.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


class CreateProductView(APIView):
    def post(self, request, isAdmin):
        name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        isAdmin = request.data.get('isAdmin')

        if isAdmin == True:
            try:
                product = Products.objects.create(
                    name=name,
                    description=description,
                    price=price
                )
                product.save()
                return JsonResponse({'message': 'Product created successfully'}, status=201)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({'error': 'You don\'t have access.'}, status=403)


class ReadProductView(APIView):
    def get(self, request):
        token = request.session.get('access_token')
        decode_token = jwt.decode(token, 'secret', algorithms=["HS256"])
        print(decode_token['user_id'])
        products = Products.objects.all()
        serializer = ProductsSerializer(products, many=True)
        return JsonResponse(serializer.data, safe=False)


class UpdateProductView(APIView):
    def put(self, request, id,isAdmin):
        name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        isAdmin= request.data.get('isAdmin')

        if isAdmin == True:
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
            return JsonResponse({'error': 'You don\'t have access.'}, status=403)


class DeleteProductView(APIView):
    def delete(self, request, id, isAdmin):
        if isAdmin == True:
            try:
                product = Products.objects.get(id=id)
                product.delete()
                return JsonResponse({'message': 'Product deleted successfully'})
            except Products.DoesNotExist:
                return JsonResponse({'error': 'Product not found'}, status=404)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        else:
            return JsonResponse({'error': 'You don\'t have access.'}, status=403)



class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UsersSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT id, password FROM users WHERE email=%s", [email])
                    user_data = cursor.fetchone()

                    if user_data:
                        user_id, hashed_password = user_data
                        if check_password(password, hashed_password):
                            
                            refresh = RefreshToken.for_user(Users.objects.get(id=user_id))
                            access_token = generate_access_token(user_id)
                            # access_token = str(refresh.access_token)
                            refresh_token = str(refresh)
                            request.session['access_token'] = access_token
                            request.session.save()
                            

                            response = JsonResponse({
                                'access': access_token,
                                'refresh': refresh_token,
                            })
                            response.set_cookie('access', access_token, httponly=True, secure=True)
                            response.set_cookie('refresh', refresh_token, httponly=True, secure=True)
                            return response
                        else:
                            return JsonResponse({'error': 'Invalid credentials'}, status=400)
                    else:
                        return JsonResponse({'error': 'Invalid credentials'}, status=400)
            except Exception as e:
                print(f"Error: {e}")
                return JsonResponse({'error': 'An error occurred'}, status=500)
        else:
            return JsonResponse(serializer.errors, status=400)

        
        
class LogoutView(APIView):
    def post(self, request):
        response = JsonResponse({'message': 'Logged out successfully'})
        response.delete_cookie('token')
        return response
