from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from .models import Users, Products
from .serializers import UsersSerializer, ProductsSerializer
import mysql.connector
import bcrypt

connexion = mysql.connector.connect(
    host='localhost',
    user='root',
    password='071099',
    database='soap'
)

def create_user(lastname, firstname, email, password):
    
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor = connexion.cursor()
        cursor.execute("""
            INSERT INTO users (lastname, firstname, email, password)
            VALUES (%s, %s, %s, %s)          
        """, (lastname, firstname, email, hashed_password))
        connexion.commit()
    except mysql.connector.Error as err:
        print("Error:", err)

def read_users(role_id):
    if role_id == 2:
        try:
            cursor = connexion.cursor()
            cursor.execute("SELECT * FROM users")
            for row in cursor:
                print(row)
            cursor.close()
        except mysql.connector.Error as err:
            print("Error:", err)
        else:
          print("You don't have access.")       

def update_user(id, lastname, firstname, email, password):
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor = connexion.cursor()
        cursor.execute("""
            UPDATE users
            SET lastname = %s,
                firstname = %s,
                email = %s,
                password = %s
            WHERE id = %s
        """, (lastname, firstname, email, hashed_password, id))
        connexion.commit()
        cursor.close()
    except mysql.connector.Error as err:
        print("Error:", err)

def delete_user(id):
    try:
        cursor = connexion.cursor()
        cursor.execute("""
            DELETE FROM users
            WHERE id = %s
        """, (id,))
        connexion.commit()
        cursor.close()
    except mysql.connector.Error as err:
        print("Error:", err)
        
      
def create_products(name, description, price, roles):
    if roles == 'admin':
        try:
            cursor = connexion.cursor()
            cursor.execute("""
                INSERT INTO products (name, description, price)
                VALUES (%s, %s, %s)          
            """, (name, description, price))
            connexion.commit()
        except mysql.connector.Error as err:
            print("Error:", err)
        else:
          print("You don't have access.")      
 
    
def read_products():
    try:
        cursor = connexion.cursor()
        cursor.execute("SELECT * FROM products")
        for row in cursor:
            print(row)
    except mysql.connector.Error as err:
        print("Error:", err)


def update_products(id, name, description, price, roles):
    if roles == 'admin':
        try:
            cursor = connexion.cursor()
            cursor.execute("""
             UPDATE products
             SET name = %s,
             description = %s,
             price = %s
            
            WHERE id = %s
        """, (name, description, price, id)) 
            connexion.commit()
        except mysql.connector.Error as err:
                print("Error:", err)
        else:
            print("You don't have access.")   
    
def delete_products(id,roles):
    if roles == 'admin':
        try:
            cursor = connexion.cursor()
            cursor.execute("""
                DELETE FROM products
                WHERE id = %s
            """, (id,)) 
            connexion.commit()
        except mysql.connector.Error as err:
            print("Error:", err)
        else:
            print("You don't have access.")   
        
        
class UsersViewSet(viewsets.ModelViewSet):
    
    queryset = Users.objects.all()
    serializer_class = UsersSerializer(data=request.data)
    permission_classes = (IsAuthenticated, )
    filtersest_fields = ['Lastname','Firstname']

class ProductsViewSet(viewsets.ModelViewSet):
    
    queryset = Products.objects.all()
    serializer_class = ProductsSerializer
    permission_classes = (IsAuthenticated, )
