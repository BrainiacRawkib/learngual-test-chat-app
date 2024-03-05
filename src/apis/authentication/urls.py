from django.urls import path

from apis.authentication import views as auth_views


app_name = "authentication"

urlpatterns = [
    path(
        'token',
        auth_views.TokenAPIView.as_view(),
        name='token'
    ),
    path(
        'login',
        auth_views.login,
        name='login'
    ),
    path(
        'password-change',
        auth_views.ChangePasswordAPIView.as_view(),
        name='password-change'
    ),
    path(
        'set-password',
        auth_views.SetPasswordAPIView.as_view(),
        name='set-password'
    ),
    path(
        'password-reset',
        auth_views.ResetPasswordAPIView.as_view(),
        name='password-reset'
    ),
    path(
        'verify-password-reset-link',
        auth_views.VerifyPasswordResetTokenAPIView.as_view(),
        name='verify-password-reset-link'
    ),
    path(
        'forgot-password',
        auth_views.ForgotPasswordAPIView.as_view(),
        name='forgot-password'
    )
]
