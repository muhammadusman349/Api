from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager,PermissionsMixin)
from django.db import models

# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self,email, password=None):
        if email is None:
            raise TypeError('User should have a Email')
        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self,email,password):
        if password is None:
            raise TypeError('Password should not be none')
        user = self.create_user(email,password=password)
        
        user.is_superuser = True
        user.is_staff = True
        user.is_verified = True
        user.is_approved = True
        user.save()
        return user
    

class User(AbstractBaseUser, PermissionsMixin):
    first_name  = models.CharField(max_length=120)
    last_name  = models.CharField(max_length=120)
    full_name  = models.CharField(max_length=120)
    email  = models.EmailField(max_length=255, unique=True, db_index=True)
    phone = models.CharField(max_length=100,null=True)
    is_approved = models.BooleanField(default= False)
    is_verified = models.BooleanField(default= False)
    is_active = models.BooleanField(default= True)
    is_staff = models.BooleanField(default= False)
    is_owner = models.BooleanField(default= False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    objects = UserManager()
    
    
    def __str__(self):
        return (self.email)   

      
      
    # def has_perm(self, perm, obj=None):
    #     return self.is_superuser
    
    # def has_module_perms(self, app_label):
    #     return True

class OtpVerify(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.IntegerField()
    
    def __str__(self):
        return str(self.user)  
