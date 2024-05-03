# import ..., include
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from ap.urls import router as path_router
from django.contrib import admin
from django.urls import path, include


router = routers.DefaultRouter()
router.registry.extend(path_router.registry)



urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(router.urls)),
    
   

]

    
