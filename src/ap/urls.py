from django.urls import path
from .views import (
    CreateUserView,
    ReadUsersView,
    UpdateUserView,
    DeleteUserView,
    CreateProductView,
    ReadProductView,
    UpdateProductView,
    DeleteProductView,
    LoginView,
    LogoutView,
)

urlpatterns = [
    path('users/create/', CreateUserView.as_view(), name='create_user'),
    path('users/read/', ReadUsersView.as_view(), name='read_users'),
    path('users/update/<int:id>/', UpdateUserView.as_view(), name='update_user'),
    path('users/delete/<int:id>/', DeleteUserView.as_view(), name='delete_user'),
    path('products/create/', CreateProductView.as_view(), name='create_product'),
    path('products/read/', ReadProductView.as_view(), name='read_products'),
    path('products/update/<int:id>/', UpdateProductView.as_view(), name='update_product'),
    path('products/delete/<int:id>/', DeleteProductView.as_view(), name='delete_product'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
]