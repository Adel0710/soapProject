from django.db import models

from django.db import models


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

    class Meta:
        managed = False
        db_table = 'products'


class Roles(models.Model):
    id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'roles'


class Users(models.Model):
    lastname = models.CharField(max_length=100, blank=True, null=True)
    firstname = models.CharField(max_length=100, blank=True, null=True)
    email = models.CharField(max_length=255, blank=True, null=True)
    purchase_number = models.IntegerField(blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    role_id = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'users'
