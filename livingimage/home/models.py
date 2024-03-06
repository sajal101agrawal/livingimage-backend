from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import MinValueValidator

# ------------------------copied from keywordlit project------------------------------------------------------------------------------

class TimeStampModel(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# --------------------------------------------UserManager Code By Adil-------------------------------------------------------------
class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        """ 
        Create a normal user instead of super user with his/ her personal details.
        """
        if not email:
            raise ValueError('User must have an email address')
        if not username:
            raise ValueError('User must have a username')

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Superuser must have an email address')

        email = self.normalize_email(email)
        #user = self.model(email=email, username=email, is_staff=True, is_superuser=True, **extra_fields)
        user = self.model(email=email, is_staff=True, is_superuser=True, **extra_fields)
        #user = self.model(email=email, is_admin = True, is_staff=True, is_superuser=True, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class openai_account(TimeStampModel):
    STATUS = (
        ('ACTIVE','ACTIVE'),
        ('INACTIVE','INACTIVE'),
    )
    id = models.BigAutoField(primary_key=True)
    key_name = models.CharField(max_length=100)
    key = models.TextField()
    busy = models.BooleanField(default=False)
    status = models.CharField(max_length=25,choices=STATUS,default='ACTIVE')



#-----------------------------------------------------Code BY Adil-------------------------------------------------------------
class CustomUser(AbstractUser,TimeStampModel):
    """ 
    This models is create to store and edit the New registered User's Data and edit Django defualt User authentication 
    """
    GENDER = (
        ('MALE', 'MALE'),
        ('FEMALE', 'FEMALE'),
        ('CUSTOM', 'CUSTOM'),
    )

    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=25)
    verification_code = models.BigIntegerField(null=True, blank=True)
    is_user_verified = models.BooleanField(default=False)
    credit = models.BigIntegerField(default=1000)
    #Mobile_number = models.IntegerField(default=0)
    #gender = models.CharField(max_length=25, choices=GENDER, null=True, blank=True)
    REQUIRED_FIELDS = ["email","is_user_verified"]

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_staff

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True 
#-----------------------------------------------------Code BY Adil-------------------------------------------------------------

class History(TimeStampModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    image_data = models.ImageField(upload_to="myimage")
    # membership = models.CharField(max_length=25)
    prompt = models.TextField()
    frequency_type = models.CharField(max_length=25)
    frequency = models.IntegerField()
    public = models.BooleanField(default=False)




class DepositeMoney(TimeStampModel):
    METHOD = (
        ('CREDIT_CARD','CREDIT_CARD'),
        ('DEBIT_CARD','DEBIT_CARD'),
    )
    STATUS = (
        ('COMPLETE','COMPLETE'),
        ('INPROCESS','INPROCESS'),
        ('DECLINED','DECLINED'),
    )
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser,on_delete=models.CASCADE)
    Amount = models.BigIntegerField()
    TransactionId = models.CharField(max_length=255)
    method = models.CharField(max_length=255,choices=METHOD)
    status =  models.CharField(max_length=25,choices=STATUS)





# ------------------------copied from keywordlit project------------------------------------------------------------------------------




class Image(TimeStampModel):
    frequency_type_choice = (
        ('week', 'Week'),
        ('day', 'Day'),
        ('month', 'Month'),
        ('year', 'Year'),
    )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    photo = models.ImageField(upload_to="myimage")
    prompt = models.TextField(max_length=200)
    frequency_type = models.CharField(max_length=25, choices=frequency_type_choice)
    frequency = models.IntegerField(validators=[MinValueValidator(1)])
    public = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)  # Call the parent class's save() method

        # Save image data to History
        History.objects.create(
            user=self.user,  # Assuming you have a user field in the Image model
            image_data=self.photo,
            prompt=self.prompt,
            frequency_type=self.frequency_type,
            frequency=self.frequency,
            public=self.public
        )


 


# Specify unique related_name attributes for the reverse relationships
CustomUser._meta.get_field('groups').remote_field.related_name = 'customuser_groups'
CustomUser._meta.get_field('user_permissions').remote_field.related_name = 'customuser_user_permissions'

