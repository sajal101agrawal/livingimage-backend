from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
from .forms import CustomUserCreationForm, CustomUserChangeForm
# Register your models here.


class ImageAdmin(admin.ModelAdmin):
 list_display = ["user",'id', 'photo', 'image_name', 'public', 'prompt', 'frequency_type', 'frequency', 'created', 'updated','regenerated_at','nextregeneration_at']


class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    list_display = ["email", "username", 'is_user_verified', 'credit']


class HistoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'image_data', 'public', 'frequency_type', 'frequency', 'created', 'updated','tag','image_name']
    search_fields = ['user__username', 'created']
    list_filter = ['public', 'created']





class CreditPricingAdmin(admin.ModelAdmin):
    list_display = ['price']

class RegeneratedImageAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'original_image_id', 'original_image_name', 'public', 'regenerated_image', 'regenerated_at', 'nextregeneration_at', 'created', 'updated']
    search_fields = ['user__username', 'created']
    list_filter = ['public', 'created']



admin.site.register(RegeneratedImage,RegeneratedImageAdmin)

admin.site.register(CreditPricing,CreditPricingAdmin)

admin.site.register(openai_account)

admin.site.register(History, HistoryAdmin)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Image, ImageAdmin)