from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import redirect
from django.contrib.auth import authenticate
from .models import Users, Products
from .serializers import UsersSerializer, ProductsSerializer, LoginSerializer
from django.conf import settings
from django.contrib.auth.hashers import make_password
import jwt

class CreateUserView(APIView):
    def post(self, request):
        lastname = request.data.get('lastname')
        firstname = request.data.get('firstname')
        email = request.data.get('email')
        password = make_password(request.data.get('password'))

        try:
            user = Users.objects.create(
                lastname=lastname,
                firstname=firstname,
                email=email,
                password=password
            )
            user.save()
            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReadUsersView(APIView):
    # permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role_id == 2:
            users = Users.objects.all()
            serializer = UsersSerializer(users, many=True)
            return Response(serializer.data)
        else:
            return Response({'error': 'You don\'t have access.'}, status=status.HTTP_403_FORBIDDEN)

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
            return Response({'message': 'User updated successfully'})
        except Users.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteUserView(APIView):
    def delete(self, request, id):
        try:
            user = Users.objects.get(id=id)
            user.delete()
            return Response({'message': 'User deleted successfully'})
        except Users.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
                return Response({'message': 'Product created successfully'}, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'You don\'t have access.'}, status=status.HTTP_403_FORBIDDEN)

class ReadProductView(APIView):
    def get(self, request):
        products = Products.objects.all()
        serializer = ProductsSerializer(products, many=True)
        return Response(serializer.data)

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
                return Response({'message': 'Product updated successfully'})
            except Products.DoesNotExist:
                return Response({'error': 'Product not found'}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'You don\'t have access.'}, status=status.HTTP_403_FORBIDDEN)

class DeleteProductView(APIView):
    def delete(self, request, id, roles):
        if roles == 'admin':
            try:
                product = Products.objects.get(id=id)
                product.delete()
                return Response({'message': 'Product deleted successfully'})
            except Products.DoesNotExist:
                return Response({'error': 'Product not found'}, status=status.HTTP_404_NOTFOUND)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({'error': 'You don\'t have access.'}, status=status.HTTP_403_FORBIDDEN)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        user = authenticate(request, email=email, password=password)
        
        if user:
            token = jwt.encode({'user_id': user.id}, settings.SECRET_KEY, algorithm='HS256')
            response = Response({'token': token})
            response.set_cookie('token', token)  
            return response
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    def post(self, request):
        response = Response({'message': 'Logged out successfully'})
        response.delete_cookie('token') 
        return response