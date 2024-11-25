from rest_framework.permissions import BasePermission
#this code use for ROLE Base
class IsAdmin(BasePermission):
    """
    Allows access only to users who are members of the 'Admin' role.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and belongs to the 'Admin' group
        return bool(request.user and request.user.groups.filter(name='Admin').exists())

class IsManager(BasePermission):
    """
    Allows access only to users who are members of the 'Manager' role.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and belongs to the 'Manager' group
        return bool(request.user and request.user.groups.filter(name='Manager').exists())

class IsDeveloper(BasePermission):
    """
    Allows access only to users who are members of the 'Developer' role.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and belongs to the 'Developer' group
        return bool(request.user and request.user.groups.filter(name='Developer').exists())
    
#EXTRA this code use for PERMISSION Base
class CanCreateUser(BasePermission):
    """
    Allows access only to users who can create new user.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.has_perm('otau_auth_mgr.ota_create_user'))

class CanUploadAPK(BasePermission):
    """
    Allows access only to users who can upload APK.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.has_perm('otau_auth_mgr.ota_upload_apk'))

class CanReleaseProduct(BasePermission):
    """
    Allows access only to users who can release product.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.has_perm('otau_auth_mgr.ota_release_product'))