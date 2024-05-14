from rest_framework import serializers
from .models import Users, Products

class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'
        
class ProductsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Products
        fields = '__all__'        
        
class UsersDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = '__all__'       
        
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    lastname = serializers.CharField()
    firstname = serializers.CharField() 

