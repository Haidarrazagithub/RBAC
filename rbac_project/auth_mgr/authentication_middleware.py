from django.utils.deprecation import MiddlewareMixin

from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.urls import resolve, Resolver404
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed

class AuthenticationCheckMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Skip certain URLs like login and registration
        if request.path in ['/otau/auth/login/', '/otau/admin/', '/favicon.ico']:
            return None

        try:
            # Check if the URL is valid
            resolve(request.path)
            jwt_authenticator = JWTAuthentication()
            try:
                auth_result = jwt_authenticator.authenticate(request)

                if auth_result:
                # Unpack user and token if authentication is successful
                    user, token = auth_result
                    request.user = user  # Attach user to the request object for further use
            
            except InvalidToken:
                return JsonResponse({"message": "Invalid token provided"}, status=401)

            except AuthenticationFailed:
                return JsonResponse({"message": "User does not exist or token is invalid"}, status=401)


        except Resolver404:
            return JsonResponse({"message": "Endpoint Not Found"}, status=404)
        except Exception as e:
            print("Error in Authorization: " + str(e))
            return JsonResponse({"message": "Internal Server Error"}, status=401)

        return None  # Allow request to proceed if authenticated
