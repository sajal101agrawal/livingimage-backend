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


#--------------------------------------------------Membership Models----------------------------------------------------------------
class Membership(models.Model):
    name = models.CharField(max_length=100)             # Added for Stripe
    price = models.DecimalField(max_digits=10, decimal_places=2)           # Added for Stripe
    duration_days = models.IntegerField()               # Added for Stripe
    credits = models.IntegerField()               # Added for Stripe
    stripe_price_id = models.CharField(max_length=100, null=True, blank=True)  # Added this field for Monthly Subscription ---> Value will be taken from Stripe Product
    membership_feature_1 = models.CharField(max_length=100, null=True, blank=True) 
    membership_feature_2 = models.CharField(max_length=100, null=True, blank=True) 
    membership_feature_3 = models.CharField(max_length=100, null=True, blank=True) 
    membership_feature_4 = models.CharField(max_length=100, null=True, blank=True) 
    membership_feature_5 = models.CharField(max_length=100, null=True, blank=True) 

    def __str__(self):
        return self.name
#--------------------------------------------------Membership Models----------------------------------------------------------------




#-----------------------------------------------------Code BY Adil-------------------------------------------------------------
class CustomUser(AbstractUser,TimeStampModel):
    """ 
    This models is create to store and edit the New registered User's Data and edit Django defualt User authentication 
    """

    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=25)
    verification_code = models.BigIntegerField(null=True, blank=True)
    is_user_verified = models.BooleanField(default=False)
    credit = models.BigIntegerField(default=100)
    #Mobile_number = models.IntegerField(default=0)
    #gender = models.CharField(max_length=25, choices=GENDER, null=True, blank=True)
    profile_photo = models.ImageField(upload_to='profile_pic/', blank=True, null=True) #default='default-user-profile.jpg')
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)  # Added for Stripe
    is_subscribed = models.BooleanField(default=False)  # Added for Stripe
    membership = models.ForeignKey(Membership, null=True, blank=True, on_delete=models.SET_NULL)  # Added for Stripe
    membership_expiry = models.DateTimeField(null=True, blank=True)  
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
    tag_choice =(
        ('update','update'),
        ('delete','delete'),
        ('create','create'),
    )
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    image_data = models.ImageField()#upload_to="myimage")
    image_name = models.CharField(max_length=255)
    # membership = models.CharField(max_length=25)
    prompt = models.TextField()
    frequency_type = models.CharField(max_length=25)
    frequency = models.IntegerField()
    public = models.BooleanField(default=False)
    tag = models.CharField(max_length=255,choices=tag_choice,default='create')




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
        ('hour', 'Hour'),
        ('minute', 'Minute'),
        ('second', 'Second'),
    )
    id=models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    photo = models.ImageField(blank=True, null=True)#upload_to="myimage")
    image_name = models.CharField(max_length=255)
    prompt = models.TextField(max_length=200,null=True, blank=True)  # PROMPT IS NOW OPTIONAL
    frequency_type = models.CharField(max_length=25, choices=frequency_type_choice)
    frequency = models.IntegerField(validators=[MinValueValidator(1)])
    public = models.BooleanField(default=False)
    regenerated_at = models.DateTimeField(null=True, blank=True)  # Null initially, updated when regenerated image is uploaded
    nextregeneration_at = models.DateTimeField()
    user_image_name=models.CharField(max_length=250, null =True, blank =True)
    tag=models.CharField(max_length=200, null =True, blank =True)
    description=models.TextField( null =True, blank =True)
 

class RegeneratedImage(TimeStampModel):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    original_image_id = models.PositiveIntegerField()
    original_image_name = models.CharField(max_length=255)
    public = models.BooleanField(default=False)  # Field from the original image model
    regenerated_image = models.ImageField()#upload_to="regenerated_images")
    regenerated_at = models.DateTimeField(null=True, blank=True)  # Null initially, updated when regenerated image is uploaded
    nextregeneration_at = models.DateTimeField()
    original_image_key_id = models.ForeignKey(Image, on_delete=models.CASCADE, related_name='regenerated_images')

    def __str__(self):
        return f"Regenerated Image {self.id} for User {self.user.email}"


# from django.db.models.signals import pre_delete
# from django.dispatch import receiver

# @receiver(pre_delete, sender=Image)
# def delete_regenerated_image(sender, instance, **kwargs):
#     # Delete corresponding RegeneratedImage when an Image is deleted
#     RegeneratedImage.objects.filter(original_image_id=instance.id).delete()

# @receiver(pre_delete, sender=RegeneratedImage)
# def delete_original_image(sender, instance, **kwargs):
#     # Delete corresponding Image when a RegeneratedImage is deleted
#     Image.objects.filter(id=instance.original_image_id).delete()




#---------------------------------------------------Credit Pricing Models-------------------------------------------------------------
class CreditPricing(models.Model):
    price = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)

    def __str__(self):
        return f"Credit Pricing per credit is : {self.price} USD"

#---------------------------------------------------Credit Pricing Models-------------------------------------------------------------


#--------------------------------------------------Subscription Models----------------------------------------------------------------
# class Subscription(models.Model):
#     user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)    # Added for Stripe
#     stripe_subscription_id = models.CharField(max_length=100)         # Added for Stripe
#     status = models.CharField(max_length=20)                     # Added for Stripe
#     current_period_end = models.DateTimeField()                # Added for Stripe
#--------------------------------------------------Subscription Models----------------------------------------------------------------



 
#---------------------------------------------------Payment Models-------------------------------------------------------------

class PaymentRecord(TimeStampModel):
    id = models.BigAutoField(primary_key=True)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_credits = models.IntegerField()
    date_time = models.DateTimeField()
    # payment_status = models.CharField(max_length=100)
    payment_status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('Paid', 'Paid'), ('Failed', 'Failed')]) # Added for Stripe
    payment_id = models.CharField(max_length=100)
    payment_mode = models.CharField(max_length=100)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    membership = models.ForeignKey(Membership, null=True, blank=True, on_delete=models.SET_NULL)  # Added for Stripe
    payment_description = models.TextField(null=True, blank=True)

class CreditHistory(TimeStampModel):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    total_credits_deducted = models.IntegerField()
    type_of_transaction = models.CharField(max_length=100)
    date_time = models.DateTimeField()
    payment_id = models.CharField(max_length=100)
    description = models.TextField()
    credit_balance_left = models.IntegerField()

#---------------------------------------------------Payment Models-------------------------------------------------------------





# Specify unique related_name attributes for the reverse relationships
CustomUser._meta.get_field('groups').remote_field.related_name = 'customuser_groups'
CustomUser._meta.get_field('user_permissions').remote_field.related_name = 'customuser_user_permissions'

