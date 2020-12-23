from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django.utils.translation import ugettext_lazy as _
from .models import User, Post, Category, PriceHistory


class MyUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = '__all__'


class MyUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('email',)


class MyUserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('name',)}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    form = MyUserChangeForm
    add_form = MyUserCreationForm
    list_display = ('email', 'name', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('email', 'name')
    ordering = ('email',)


admin.site.register(User, MyUserAdmin)


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ('id', 'author', 'title', 'created_at')
    list_display_links = ('title',)
    search_fields = ['title']
    ordering = ('-created_at',)


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    list_display_links = ('name',)


@admin.register(PriceHistory)
class PriceHistoryAdmin(admin.ModelAdmin):
    list_display = ('post', 'user', 'created_at', 'stripe_id')
    list_display_links = ('post',)
    search_fields = ['post__title']
