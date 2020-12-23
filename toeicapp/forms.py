from django import forms
from ckeditor.widgets import CKEditorWidget
from django.contrib.auth.forms import (
    AuthenticationForm, UserCreationForm, PasswordChangeForm,
    PasswordResetForm, SetPasswordForm
)
from .models import Post
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.conf import settings
from django.core.mail import BadHeaderError, send_mail
from django.forms import ModelForm, TextInput, Textarea

User = get_user_model()


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ('title', 'category', 'content', 'thumbnail')
        widgets = {
            'text': CKEditorWidget(),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class LoginForm(AuthenticationForm):
    """ログインフォーム"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'
            # placeholderにフィールドのラベルを入れる
            field.widget.attrs['placeholder'] = field.label


class UserCreateForm(UserCreationForm):
    """ユーザー登録用フォーム"""

    class Meta:
        model = User
        fields = ('name', 'email',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_email(self):
        email = self.cleaned_data['email']
        User.objects.filter(email=email, is_active=False).delete()
        return email


class UserUpdateForm(forms.ModelForm):
    """ユーザー情報更新フォーム"""

    class Meta:
        model = User
        fields = ('name',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class MyPasswordChangeForm(PasswordChangeForm):
    """パスワード変更フォーム"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class MyPasswordResetForm(PasswordResetForm):
    """パスワード忘れたときのフォーム"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class MySetPasswordForm(SetPasswordForm):
    """パスワード再設定用フォーム(パスワード忘れて再設定)"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class ContactForm(forms.Form):
    name = forms.CharField(
        label='',
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'お名前'
        })
    )
    email = forms.EmailField(
        label='',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'メールアドレス',
        })
    )
    subject = forms.CharField(
        label='',
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '件名',
        })
    )
    message = forms.CharField(
        label='',
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'placeholder': 'お問い合わせ'
        })
    )

    def send_email(self):
        message = self.cleaned_data['message']
        name = self.cleaned_data['name']
        email = self.cleaned_data['email']
        subject = self.cleaned_data['subject']
        from_email = '{name} <{email}> ({subject})'.format(
            name=name, email=email, subject=subject)
        recipient_list = [settings.EMAIL_HOST_USER]
        try:
            send_mail(subject, message, from_email, recipient_list)
        except BadHeaderError:
            return HttpResponse('無効なヘッダが検出されました。')
