from rest_framework import status,generics
from rest_framework.response import Response
from account.serializers import Registrationserializer,Loginserializer,ChangePasswordSerializer,ForgetPasswordSerializer,ResetPasswordSerializer
from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.shortcuts import render




class RegistrationApi(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    authentication_classes = []
    
    serializer_class = Registrationserializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

class LoginApiView(generics.GenericAPIView): 
    permission_classes = (AllowAny,)
    authentication_classes = []
    serializer_class = Loginserializer
    
    
    def post(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": self.request})
        if serializer.is_valid():
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(generics.GenericAPIView):
    permission_classes = []
    authentication_classes = []
    
    def post(self,request):
        logout(request)
        return Response({"msg":"Successfully Logged out"},status=status.HTTP_200_OK)



class ChangePasswordView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={
                                           'user': self.request.user})
        if serializer.is_valid():
            serializer.save()
            return Response({'password': ' password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ForgetPasswordView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = ForgetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response({'opt': 'successfully send OTP '}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ResetPasswordView(generics.GenericAPIView):
    permission_classes = []
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            return Response({'password': 'successfully set New Password'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


