from rest_framework import viewsets
import logging
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import redirect
from django.contrib.auth import authenticate
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import get_user_model
from .models import Users, Products
from .serializers import UsersSerializer, ProductsSerializer, LoginSerializer
from django.conf import settings
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
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
   authentication_classes = [JWTAuthentication]
permission_classes = [IsAuthenticated] 

def get(self, request):
      
        users = Users.objects.all()
        serializer = UsersSerializer(users, many=True)
        return JsonResponse(serializer.data)
        # else:
        #     return Response({'error': 'You don\'t have access.'}, status=status.HTTP_403_FORBIDDEN)

class UpdateUserView(APIView):
    def put(self, request, id):
        lastname = request.data.get('lastname')
        firstname = request.data.get('firstname')
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
    def post(self, request):
        name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        roles = request.data.get('roles')

        if roles == 'admin':
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
        products = Products.objects.all()
        serializer = ProductsSerializer(products, many=True)
        return JsonResponse(serializer.data)

class UpdateProductView(APIView):
    def put(self, request, id):
        name = request.data.get('name')
        description = request.data.get('description')
        price = request.data.get('price')
        roles = request.data.get('roles')

        if roles == 'admin':
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
    def delete(self, request, id, roles):
        if roles == 'admin':
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
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        user = authenticate(request, email=email, password=password)
        
        if user:
            token = jwt.encode({'user_id': user.id}, settings.SECRET_KEY, algorithm='HS256')
            response = JsonResponse({'token': token})
            response.set_cookie('token', token)  
            return response
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status='à&')

class LogoutView(APIView):
    def post(self, request):
        response =JsonResponse({'message': 'Logged out successfully'})
        response.delete_cookie('token') 
        return response