from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.utils.translation import gettext_lazy as _

class CustomUserCreationForm(forms.ModelForm):
    password1 = forms.CharField(label=_("Password"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password confirmation"), widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'employee_number', 'role', 'department')

    def clean_password2(self):
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError(_("Passwords don't match"))
        return p2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class CustomUserChangeForm(forms.ModelForm):
    """
    A form for updating users. Includes a read-only password hash field.
    """
    password = ReadOnlyPasswordHashField(label=_("Password"))

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'employee_number', 'role', 'department', 'password', 'is_active', 'is_staff')


class CustomUserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'is_approved', 'employee_number', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_superuser', 'is_active')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'employee_number')
    ordering = ('username',)

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'employee_number', 'picture', 'department')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser','is_approved', 'is_rejected', 'groups', 'user_permissions')}),
        ('Dates', {'fields': ('date_joined',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'employee_number', 'role', 'password1', 'password2'),
        }),
    )


admin.site.register(CustomUser, CustomUserAdmin)
