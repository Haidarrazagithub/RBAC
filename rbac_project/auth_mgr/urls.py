from django.urls import path,re_path
from .views import OTALogin,OTALogout,OTAUserListManagement,PermListManagement,OTAUserPasswordManagement,ResetPasswordToUser,\
UserRoleListManagement,SomeView,AnotherView,DeveloperView

urlpatterns = [
    path('login/', OTALogin.as_view()),
    path('logout/', OTALogout.as_view()),
    path('reset_password/', ResetPasswordToUser.as_view()),
    path('permissions/', PermListManagement.as_view()),
    path('users/', OTAUserListManagement.as_view()),
    path('user_roles/', UserRoleListManagement.as_view()),
    re_path('^users/(?P<user_id>[0-9]+)/$', OTAUserPasswordManagement.as_view()),
    #for testing role base demo url
    path('only_admin/', SomeView.as_view()),
    path('only_manager/', AnotherView.as_view()),
    path('only_developer/', DeveloperView.as_view())


]