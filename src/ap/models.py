from django.db import models
from django.contrib.auth.models import BaseUserManager 
from django.contrib.auth.hashers import make_password

class Cart(models.Model):
    content = models.IntegerField(blank=True, null=True)
    price = models.IntegerField(blank=True, null=True)
    date_of_order = models.DateField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'cart'


class Extras(models.Model):
    id = models.IntegerField(primary_key=True)
    nom = models.CharField(max_length=100, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    price = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'extras'


class Orders(models.Model):
    id = models.IntegerField(primary_key=True)
    produit = models.IntegerField(blank=True, null=True)
    user_id = models.IntegerField(blank=True, null=True)
    order_date = models.DateField(blank=True, null=True)
    price = models.IntegerField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'orders'


class Products(models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    price = models.IntegerField(blank=True, null=True)
    image = models.TextField(blank=True, null=True)
    isAdmin = models.BooleanField(default=False)

    class Meta:
        managed = False
        db_table = 'products'



        
        
class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        
        if not email:
            raise ValueError('L\'adresse e-mail est obligatoire')

        user = self.model(
            email=self.normalize_email(email),
            
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
      
        user = self.create_user(
            email,
            password=password,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user        


class Users(models.Model):
    
    firstname = models.CharField(max_length=100, blank=True, null=True)
    lastname = models.CharField(max_length=100, blank=True, null=True)
    email = models.CharField(max_length=255, blank=True, null=True)
    password = models.CharField(max_length=255, blank=False, null=False)
    isAdmin = models.BooleanField(default=False)
    
    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    class Meta:
        managed = False
        db_table = 'users'

def get_user_data(user_id):
    """Récupère les données de l'utilisateur à partir de l'ID de l'utilisateur."""
    try:
        user = Users.objects.get(id=user_id)
        return {
            'id': user.id,
            'email': user.email,
            'password': user.password
            
        }
    except Users.DoesNotExist:
        raise Exception('Utilisateur non trouvé')