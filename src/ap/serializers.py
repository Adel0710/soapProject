from rest_framework import serializers
from django.contrib.auth import get_user_model  
from .models import Users, Products

class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'firstname', 'lastname', 'email', 'password', 'role_id']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = Users(**validated_data)
        user.set_password(password)
        user.save()
        return user
        
class ProductsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = '__all__'        
        
class UsersDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'       
        
class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['lastname', 'firstname','email', 'password']

