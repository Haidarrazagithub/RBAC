import base64
import re

from django.contrib.auth import authenticate,logout,get_user_model
from django.utils import timezone
from django.contrib.auth.models import Permission,Group
from django.contrib.auth.hashers import make_password

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import OTP
from .serializers import UserListWithPermissionSerializer,UserListWithRoleSerializer
from utils.custom_permissions import IsAdmin,IsManager,IsDeveloper
from utils.common import sendEmail

User = get_user_model()

# Helper functions for OTP management
def send_otp_to_user(user):
    """Checks for an existing valid OTP or generates a new one for the user."""

    # Check if there is an existing non-expired OTP for the user
    existing_otp = OTP.objects.filter(user=user, expires_at__gt=timezone.now()).first()
    
    if existing_otp:
        # If a valid OTP exists, reuse it
        otp_code = existing_otp.otp_code
    else:
        # Delete all previous expired OTPs for the user
        OTP.objects.filter(user=user, expires_at__lt=timezone.now()).delete()
        #generate a new OTP and save it
        otp_code = OTP.generate_otp()
        OTP.objects.create(
            user=user,
            otp_code=otp_code,
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )
    
    # Send OTP email
    subject = "OTP for OTA User Authentication"
    message = (
        f"Hello,\n\n{otp_code} is your OTP for OTA User Authentication. "
        "This OTP is valid for 10 minutes.\n\nThanks,\nRBAC,Haidar."
    )
    print("OTP Email message: ",message)
    return otp_code
    """ #use production 
    if sendEmail(subject, message, user.username):
        return otp_code  # Successful email sent
    else:
        return None  # Email sending failed
    """

def verify_otp(user, otp_code):
    otp_record = OTP.objects.filter(user=user, otp_code=otp_code).first()
    if otp_record and not otp_record.is_expired():
        return otp_record
    return None

def is_valid_email(email):
    """
    Validate an email address using a regular expression.
    Returns True if the email is valid, False otherwise.

    """
    email_regex = r'^(?!.*\.\.|.*@@)(?=.*@).*$'
    return True if re.match(email_regex, email) else False


class OTALogin(APIView):

    def decode_user_credential(self,auth_header):
        
        decoded_header = base64.b64decode(auth_header)
        credentials = str(decoded_header)[2:len(str(decoded_header)) - 1]
        separate_credentials = credentials.split(':')
        username = separate_credentials[0].lower()

        password = ''
        for x in range(len(separate_credentials)):
            if x != 0:
                password = password + separate_credentials[x] + ':'
        password = password[:-1]
        print(username,password)
        return username, password
    
    def post(self, request):
        """
        Handle login with single API for OTP generation and verification.
        If 'otp_code' is provided, verify it. If not, generate and send OTP.
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION', None)
        if auth_header is None:
            response_data = {'message': "Please Provide Authorization Credentials"}
            return Response(response_data, status=status.HTTP_401_UNAUTHORIZED)
        try:
            username, password = self.decode_user_credential(auth_header)
            user = authenticate(username=username, password=password)
            
            if user is not None:
                if not user.ota_active:
                    # Check if OTP code is provided
                    otp_code = request.data.get("otp_code")
                    if otp_code:
                        # Verify the provided OTP
                        otp_record = verify_otp(user, otp_code)
                        if otp_record:
                            user.ota_active = True
                            user.is_active = True
                            user.save()
                            otp_record.delete()  # Clear OTP on successful verification
                        else:
                            return Response({'message': "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)
                    else:
                    # Generate and send OTP if no OTP code provided
                        otp_code = send_otp_to_user(user)
                        if otp_code:
                            return Response({'message': "OTP sent via email"}, status=status.HTTP_202_ACCEPTED)
                        else:
                            return Response({'message': "Failed to send OTP email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


                # Generate JWT token 
                refresh = RefreshToken.for_user(user)
                print(f"User : {request.user} is Logged IN")
                role_object = user.groups.first()
                role = role_object.name
                response_data = {
                    'message': "Login successful",
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    "status_code": status.HTTP_200_OK,
                    'user_id': user.id,
                    'email': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'role': role,
                    #for permisison base system
                #     'permissions': {
                #     'create_user': user.has_perm('otau_auth_mgr.ota_create_user'),
                #     'upload_apk': user.has_perm('otau_auth_mgr.ota_upload_apk'),
                #     'release_product': user.has_perm('otau_auth_mgr.ota_release_product')
                # }
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response({'message': "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(f"Error in OTALogin : {e}")
            response_data = {'message': 'Internal Server Error'}
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class OTALogout(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):

        # Log the user out
        print(f"User : {request.user} is Logged OUT")
        logout(request)

        response_data = {'message': "Logout successful"}
        return Response(data=response_data, status=status.HTTP_200_OK)    
    
class OTAUserListManagement(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]
    authentication_classes = [JWTAuthentication]
    
    def get(self, request, *args, **kwargs):
        try:
            users = User.objects.filter(is_superuser=False,is_deleted=False)
            #serializer = UserListWithPermissionSerializer(users, many=True)  # Serialize the queryset with perms
            serializer = UserListWithRoleSerializer(users, many=True)  # Serialize the queryset with role
            return Response({"users": serializer.data,"message":"User List Fetch"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            print(f"Error in UserPermListManagement : {e}")
            response_data = {'message': 'Internal Server Error'}
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def post(self, request):
        data = request.data
        email = data.get("email", None)
        email = email.strip() if email else None
        if not email or not is_valid_email(email):
            return Response({'message': "Please Provide Valid Email"}, status=status.HTTP_400_BAD_REQUEST)
            
        first_name = data.get("first_name", None)
        if not first_name:
            return Response({'message': "Please Provide First Name"}, status=status.HTTP_400_BAD_REQUEST)
        
        last_name = request.data.get("last_name", None)
        if not last_name:
            return Response({'message': "Please Provide Last Name"}, status=status.HTTP_400_BAD_REQUEST)

        password = request.data.get("password", None)
        password = password.strip() if password else None
        if not password:
            return Response({'message': "Please Provide Password"}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=email.lower()).exists():
            return Response({'message': "User Already Exists"}, status=status.HTTP_400_BAD_REQUEST)
        
        role = request.data.get("role", None)
        if role is None:
            return Response({'message': "Please Provide User Role"}, status=status.HTTP_400_BAD_REQUEST)
        
        group = Group.objects.filter(id=role).first()
        if group is None:
            raise Response({'message': "Please Provide Correct Role"}, status=status.HTTP_400_BAD_REQUEST)
        
        email=email.lower()
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            ota_active=False,
            is_deleted=False
        )
        user.groups.add(group)
        # Assign permissions
        # for perm_code in data.get("permissions", []):
        #     permission = Permission.objects.filter(codename=f"ota_{perm_code}").first()
        #     if permission:
        #         user.user_permissions.add(permission)
        print(f"New User : {user} is Created")
        return Response({'message': "User created", 'user_id': user.id}, status=status.HTTP_201_CREATED)
    
    def delete(self, request):
        """Perticuler User DELETE"""
        user_id=request.data.get("user_id")
        if not user_id:
            return Response({'message': "Please Provide User Id"}, status=status.HTTP_404_NOT_FOUND)
        user = User.objects.filter(id=user_id, is_deleted=False).first()
        if request.user==user:
            return Response({'message': "Unauthorized User"}, status=status.HTTP_401_UNAUTHORIZED)
        if user:
            user.is_deleted = True
            user.is_active = False
            user.ota_active=False
            print(f"User : {user} is deleted by {request.user}")
            user.save()
            return Response({'message': "User deleted"}, status=status.HTTP_200_OK)
        return Response({'message': "User not found"}, status=status.HTTP_404_NOT_FOUND)
    
    def put(self, request):
        """Update user password and permissions."""

        user_id = request.data.get("user_id")
        user = User.objects.filter(id=user_id, is_deleted=False).first()
        
        if not user:
            return Response({'message': "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        role = request.data.get("role", None)
        if role is None:
            return Response({'message': "Please Provide User Role"}, status=status.HTTP_400_BAD_REQUEST)
        
        group = Group.objects.filter(id=role).first()
        if group is None:
            raise Response({'message': "Please Provide Correct Role"}, status=status.HTTP_400_BAD_REQUEST)
        # Update password
        new_password = request.data.get("new_password")
        if new_password:
            user.password = make_password(new_password)
        #remove user from older groups
        for temp_group in user.groups.all():
                        user.groups.remove(temp_group)
        #add user to new group
        user.groups.add(group)

        #for Update permissions
        # permissions = request.data.get("permissions", [])
        # if permissions:
        #     user.user_permissions.clear()  # Clear existing permissions
        #     for perm_code in permissions:
        #         permission = Permission.objects.filter(codename=f"ota_{perm_code}").first()
        #         if permission:
        #             user.user_permissions.add(permission)
        
        print(f"User : {user} is updated by {request.user}")

        user.save()
        return Response({'message': "User updated successfully"}, status=status.HTTP_200_OK)

#added for perm base system created
class PermListManagement(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        try:
            # Filter permissions that have a specific prefix (e.g., "ota_")
            custom_permissions = Permission.objects.filter(codename__startswith='ota_')

            # Prepare permissions list with 'ota_' prefix removed from codename
            permissions_list = [
                {"id": perm.id, "permission": perm.codename.replace('ota_', '', 1)}
                for perm in custom_permissions
            ]
            return Response({"permissions": permissions_list,"message":"Permission List Fetch"}, status=status.HTTP_200_OK)
        
        except Exception as e:
            print(f"Error in UserPermListManagement : {e}")
            response_data = {'message': 'Internal Server Error'}
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OTAUserPasswordManagement(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def put(self, request, user_id):
        # Retrieve the user based on the provided user_id
        user = User.objects.filter(id=user_id, is_deleted=False).first()
        if not user:
            return Response({'message': "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Ensure the user is not a superuser, as superuser password updates are restricted
        if user.is_superuser:
            return Response({'message': "SuperUser password cannot be updated"}, status=status.HTTP_403_FORBIDDEN)

        # Confirm that the request is made by the authenticated user whose password is being changed
        if request.user != user:
            return Response({'message': "Unauthorized User"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Retrieve the new password from the request
        new_password = request.data.get("new_password")
        # Check if new password is provided
        if not new_password:
            return Response({'message': "New password not provided"}, status=status.HTTP_400_BAD_REQUEST)

        # Update the user's password and save
        user.password = make_password(new_password)
        user.save()

        return Response({'message': "Password updated successfully","user_id": user.id}, status=status.HTTP_200_OK)
        
class ResetPasswordToUser(APIView):

    def post(self, request):
        # Retrieve the user based on the provided username and check if they are a superuser
        email=request.data.get("email")
        if not email:
            return Response({'message': "Please Provide email"}, status=status.HTTP_404_NOT_FOUND)
        user = User.objects.filter(username=email.lower(), is_deleted=False).first()
        if not user:
            return Response({'message': "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Check if the specific user is a superuser
        if user.is_superuser:
            return Response({'message': "SuperUser password cannot be updated"}, status=status.HTTP_403_FORBIDDEN)
        
        
        # Check if OTP provided in request data
        otp_code = request.data.get("otp_code")
        new_password = request.data.get("new_password")
        
        # If OTP is not provided, generate and send it
        if not otp_code:
            otp_code = send_otp_to_user(user)
            if otp_code:
                return Response({'message': "OTP sent via email","user_id": user.id}, status=status.HTTP_202_ACCEPTED)
            else:
                return Response({'message': "Failed to send OTP email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # If OTP provided, verify it
        otp_record = verify_otp(user, otp_code)
        if otp_record:
            if new_password:
                user.password = make_password(new_password)
                user.ota_active =True
                user.save()
                print(f"User : {user} password updated")
                otp_record.delete()  # Clear OTP after successful password update
                return Response({'message': "Password updated successfully","user_id": user.id}, status=status.HTTP_200_OK)
            else:
                return Response({'message': "New password not provided"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)

#for user role base         
class UserRoleListManagement(APIView):
    """
    API endpoint for managing user roles.

    Permissions:
    - GET: Requires authenticated user with Create permission.
    """
    permission_classes = [IsAuthenticated, IsAdmin]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        userroles = Group.objects.values("id", "name").order_by("id")
        if not userroles:
            return Response({'message': "User Role Does not Exists"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'message': 'User Roles Fetched',
                        'user_roles': userroles},status=status.HTTP_200_OK)
    
"""Testing all Auth system Role Base demo url"""

class SomeView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Allow access only for 'Admin' users

    def get(self, request):
        return Response({"message": "Hello Admin!"})

class AnotherView(APIView):
    permission_classes = [IsAuthenticated, IsManager]  # Allow access only for 'Manager' users

    def get(self, request):
        return Response({"message": "Hello Manager!"})

class DeveloperView(APIView):
    permission_classes = [IsAuthenticated, IsDeveloper]  # Allow access only for 'Developer' users

    def get(self, request):
        return Response({"message": "Hello Developer!"})