
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import (
    LoginView, LogoutView, PasswordChangeView, PasswordChangeDoneView,
    PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
)
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.core.signing import BadSignature, SignatureExpired, loads, dumps
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect, resolve_url, render
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.views import generic
from .forms import (
    LoginForm, UserCreateForm, UserUpdateForm, MyPasswordChangeForm,
    MyPasswordResetForm, MySetPasswordForm, PostForm, ContactForm
)
from .models import Post, Category, PriceHistory
from django.views.generic import TemplateView, CreateView, DetailView, UpdateView, DeleteView, ListView
from django.contrib import messages
from django.views.generic.edit import FormView

import stripe
stripe.api_key = settings.STRIPE_SECRET_KEY

User = get_user_model()


class Index(generic.TemplateView):
    template_name = 'toeicapp/index.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        if Post.updated_at:
            post_list = Post.objects.all().order_by('-updated_at')[:6]
        else:
            post_list = Post.objects.all().order_by('-created_at')[:6]
        context = {
            'post_list': post_list,
        }
        return context


class Privacy(TemplateView):
    template_name = 'toeicapp/privacy.html'


class Service(TemplateView):
    template_name = 'toeicapp/service.html'


class AskedQuestion(TemplateView):
    template_name = 'toeicapp/asked_question.html'


class PostCreate(LoginRequiredMixin, CreateView):
    model = Post
    form_class = PostForm
    success_url = reverse_lazy('toeicapp:index')

    def form_valid(self, form):
        form.instance.author_id = self.request.user.id
        return super(PostCreate, self).form_valid(form)

    def get_success_url(self):
        messages.success(self.request, '記事を登録しました。')
        return resolve_url('toeicapp:index')


class PostDetail(generic.DetailView):
    model = Post

    def post(self, request, *args, **kwargs):
        post = self.get_object()
        token = request.POST['stripeToken']
        try:
            charge = stripe.Charge.create(
                amount=post.price,
                currency='jpy',
                source=token,
                description='メール：{} メンター名：{}'.format(
                    request.user.email, post.title),
            )
        except stripe.error.CardError as e:
            context = self.get_context_data()
            context['message'] = 'Your payment cannot be completed The card has been declined'
            return render(request, 'toeicapp/post_detail.html', context)
        else:
            PriceHistory.objects.create(
                post=post, user=request.user, stripe_id=charge.id)
            return redirect('toeicapp:index')

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['publick_key'] = settings.STRIPE_PUBLIC_KEY
        detail_data = Post.objects.get(id=self.kwargs['pk'])
        category_posts = Post.objects.filter(
            category=detail_data.category).order_by('-created_at')[:5]
        params = {
            'object': detail_data,
            'category_posts': category_posts,
            'context': context,
        }
        return params


class PostUpdate(generic.UpdateView):
    model = Post
    form_class = PostForm
    template_name = 'toeicapp/post_form.html'

    def get_success_url(self):
        messages.info(self.request, '記事を更新しました。')
        return resolve_url('toeicapp:post_detail', pk=self.kwargs['pk'])


class PostDelete(generic.DeleteView):
    model = Post

    def get_success_url(self):
        messages.info(self.request, '記事を削除しました。')
        return resolve_url('toeicapp:index')


class PostList(generic.ListView):
    model = Post
    paginate_by = 6

    def get_queryset(self):
        if Post.updated_at:
            return Post.objects.all().order_by('-updated_at')
        else:
            return Post.objects.all().order_by('-created_at')


class Login(LoginView):
    """ログインページ"""
    form_class = LoginForm
    template_name = 'toeicapp/login.html'


class Logout(LogoutView):
    """ログアウトページ"""
    template_name = 'toeicapp/logout.html'


class UserCreate(generic.CreateView):
    """ユーザー仮登録"""
    template_name = 'toeicapp/user_create.html'
    form_class = UserCreateForm

    def form_valid(self, form):
        """仮登録と本登録用メールの発行."""
        # 仮登録と本登録の切り替えは、is_active属性を使うと簡単です。
        # 退会処理も、is_activeをFalseにするだけにしておくと捗ります。
        user = form.save(commit=False)
        user.is_active = False
        user.save()

        # アクティベーションURLの送付
        current_site = get_current_site(self.request)
        domain = current_site
        context = {
            'protocol': 'https' if self.request.is_secure() else 'http',
            'domain': domain,
            'token': dumps(user.pk),
            'user': user,
        }

        subject = render_to_string(
            'toeicapp/mail_template/create/subject.txt', context)
        message = render_to_string(
            'toeicapp/mail_template/create/message.txt', context)

        user.email_user(subject, message)
        return redirect('toeicapp:user_create_done')


class UserCreateDone(generic.TemplateView):
    """ユーザー仮登録したよ"""
    template_name = 'toeicapp/user_create_done.html'


class UserCreateComplete(generic.TemplateView):
    """メール内URLアクセス後のユーザー本登録"""
    template_name = 'toeicapp/user_create_complete.html'
    timeout_seconds = getattr(
        settings, 'ACTIVATION_TIMEOUT_SECONDS', 60*60*24)  # デフォルトでは1日以内

    def get(self, request, **kwargs):
        """tokenが正しければ本登録."""
        token = kwargs.get('token')
        try:
            user_pk = loads(token, max_age=self.timeout_seconds)

        # 期限切れ
        except SignatureExpired:
            return HttpResponseBadRequest()

        # tokenが間違っている
        except BadSignature:
            return HttpResponseBadRequest()

        # tokenは問題なし
        else:
            try:
                user = User.objects.get(pk=user_pk)
            except User.DoesNotExist:
                return HttpResponseBadRequest()
            else:
                if not user.is_active:
                    # まだ仮登録で、他に問題なければ本登録とする
                    user.is_active = True
                    user.save()
                    return super().get(request, **kwargs)

        return HttpResponseBadRequest()


class OnlyYouMixin(UserPassesTestMixin):
    """本人か、スーパーユーザーだけユーザーページアクセスを許可する"""
    raise_exception = True

    def test_func(self):
        user = self.request.user
        return user.pk == self.kwargs['pk'] or user.is_superuser


class UserDetail(OnlyYouMixin, generic.DetailView):
    """ユーザーの詳細ページ"""
    model = User
    # デフォルトユーザーを使う場合に備え、きちんとtemplate名を書く
    template_name = 'toeicapp/user_detail.html'


class UserUpdate(OnlyYouMixin, generic.UpdateView):
    """ユーザー情報更新ページ"""
    model = User
    form_class = UserUpdateForm
    template_name = 'toeicapp/user_form.html'  # デフォルトユーザーを使う場合に備え、きちんとtemplate名を書く

    def get_success_url(self):
        return resolve_url('toeicapp:user_detail', pk=self.kwargs['pk'])


class PasswordChange(PasswordChangeView):
    """パスワード変更ビュー"""
    form_class = MyPasswordChangeForm
    success_url = reverse_lazy('toeicapp:password_change_done')
    template_name = 'toeicapp/password_change.html'


class PasswordChangeDone(PasswordChangeDoneView):
    """パスワード変更しました"""
    template_name = 'toeicapp/password_change_done.html'


class PasswordReset(PasswordResetView):
    """パスワード変更用URLの送付ページ"""
    subject_template_name = 'toeicapp/mail_template/password_reset/subject.txt'
    email_template_name = 'toeicapp/mail_template/password_reset/message.txt'
    template_name = 'toeicapp/password_reset_form.html'
    form_class = MyPasswordResetForm
    success_url = reverse_lazy('toeicapp:password_reset_done')


class PasswordResetDone(PasswordResetDoneView):
    """パスワード変更用URLを送りましたページ"""
    template_name = 'toeicapp/password_reset_done.html'


class PasswordResetConfirm(PasswordResetConfirmView):
    """新パスワード入力ページ"""
    form_class = MySetPasswordForm
    success_url = reverse_lazy('toeicapp:password_reset_complete')
    template_name = 'toeicapp/password_reset_confirm.html'


class PasswordResetComplete(PasswordResetCompleteView):
    """新パスワード設定しましたページ"""
    template_name = 'toeicapp/password_reset_complete.html'


class CategoryList(generic.ListView):
    model = Category


class CategoryDetail(generic.DetailView):
    model = Category
    slug_field = 'name_en'
    slug_url_kwarg = 'name_en'

    def get_context_data(self, *args, **kwargs):
        detail_data = Category.objects.get(name_en=self.kwargs['name_en'])
        category_posts = Post.objects.filter(
            category=detail_data.id).order_by('-created_at')

        params = {
            'object': detail_data,
            'category_posts': category_posts,
        }

        return params


class ContactFormView(FormView):
    template_name = 'toeicapp/contact_form.html'
    form_class = ContactForm

    def form_valid(self, form):
        form.send_email()
        return super().form_valid(form)

    def get_success_url(self):
        messages.info(self.request, 'お問い合わせは正常に送信されました。')
        return resolve_url('toeicapp:index')
