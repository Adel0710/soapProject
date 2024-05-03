from rest_framework import routers
from .views import UsersViewSet , ProductsViewSet

router = routers.DefaultRouter()
router.register('Users',UsersViewSet)
router.register('Products', ProductsViewSet)

