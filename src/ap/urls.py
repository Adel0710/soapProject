from django.urls import path
from .views import index, create_user_view, login_view, read_users_view, update_user_view, delete_user_view, create_product_view, read_product_view, update_product_view, delete_product_view

urlpatterns = [
    path('', index, name='index'),
    path('users/', create_user_view, name='create_user'),  # C'est ici
    path('login/', login_view, name='login'),
    path('users/read/', read_users_view, name='read_users'),
    path('users/update/<int:id>/', update_user_view, name='update_user'),
    path('users/delete/<int:id>/', delete_user_view, name='delete_user'),
    path('products/', create_product_view, name='create_product'),
    path('products/read/', read_product_view, name='read_products'),
    path('products/update/<int:id>/', update_product_view, name='update_product'),
    path('products/delete/<int:id>/', delete_product_view, name='delete_product'),
]
