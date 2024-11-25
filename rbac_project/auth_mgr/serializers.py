from rest_framework import serializers

from django.contrib.auth import get_user_model
User = get_user_model()

class UserListWithPermissionSerializer(serializers.ModelSerializer):
    create_user = serializers.SerializerMethodField()
    upload_apk = serializers.SerializerMethodField()
    release_product = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'create_user', 'upload_apk', 'release_product']

    def get_create_user(self, obj):
        # Check if user has 'create_user' permission
        return obj.has_perm('otau_auth_mgr.ota_create_user')

    def get_upload_apk(self, obj):
        # Check if user has 'upload_apk' permission
        return obj.has_perm('otau_auth_mgr.ota_upload_apk')

    def get_release_product(self, obj):
        # Check if user has 'realeas_product' permission
        return obj.has_perm('otau_auth_mgr.ota_release_product')
    
class UserListWithRoleSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'role']

    def get_role(self, obj):
        """
        Get the first role assigned to the user.
        Returns the role name (group) of the first assigned group.
        """
        # Fetch the first group assigned to the user (if any)
        first_role = obj.groups.first()
        return first_role.name if first_role else None