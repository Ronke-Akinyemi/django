from django.shortcuts import render
from rest_framework import (permissions, generics, views, filters)
from authentication.models import User
from rest_framework.response import Response
from rest_framework import status


# Create your views here.

class Dashboard(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    # serializer_class = UserHome
    queryset = User.objects.filter()
    def get(self, request):
        return Response(status=status.HTTP_200_OK)