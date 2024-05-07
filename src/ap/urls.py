from rest_framework import routers
from django.urls import path
from .views import UsersViewSet , ProductsViewSet ,UsersDetail

router = routers.DefaultRouter()
router.register('Users',UsersViewSet)
router.register('Products', ProductsViewSet)

# router1 = routers.SimpleRouter()
# router.register('user-detail', UsersDetail)

# urlpatterns = [
#     path('user-detail/<int:pk>',UsersDetail.as_view(), name = 'user-detail'),
# ]


