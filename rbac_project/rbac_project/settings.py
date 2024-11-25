"""
Django settings for rbac_project project.

Generated by 'django-admin startproject' using Django 4.1.3.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

from pathlib import Path
import os
from datetime import timedelta


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

ALLOWED_HOSTS = ['*']

CORS_ORIGIN_ALLOW_ALL = True
# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-&a842ktzli3_sfd^r*o)cvc@73z4v*qw=7#ge(qd7m(_uylnkn'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'auth_mgr',

]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'auth_mgr.authentication_middleware.AuthenticationCheckMiddleware',#custom Middleware

]

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True
}

ROOT_URLCONF = 'rbac_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'rbac_project.wsgi.application'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}

AUTH_USER_MODEL = 'auth_mgr.OTAUser'

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
#use for local sqlite
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# db_host = os.environ['DB_HOST'] if 'DB_HOST' in os.environ else "localhost"
# db_name = os.environ['DB_SERVER_ALIAS'] if 'DB_SERVER_ALIAS' in os.environ else "rbac"
# db_server_alias = os.environ['DB_SERVER_ALIAS'] if 'DB_SERVER_ALIAS' in os.environ else "postgres"
# db_password = os.environ['DB_INST_PASSWORD'] if 'DB_INST_PASSWORD' in os.environ else "password"
# smtp_host = os.environ['SMTP_HOST'] if 'SMTP_HOST' in os.environ else None
# smtp_port = os.environ['SMTP_PORT'] if 'SMTP_PORT' in os.environ else -1
# smtp_username = os.environ['SMTP_USERNAME'] if 'SMTP_USERNAME' in os.environ else None
# smtp_password = os.environ['SMTP_PASSWORD'] if 'SMTP_PASSWORD' in os.environ else None

# CSRF_TRUSTED_ORIGINS = ['http://localhost:4200']
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': db_name,
#         'USER': db_server_alias,
#         'PASSWORD': db_password,
#         'HOST': db_host,
#         'PORT': '5432'
#     }
# }
# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

#for production host
# EMAIL_HOST = smtp_host
# EMAIL_USE_TLS = True
# EMAIL_PORT = int(smtp_port)
# EMAIL_HOST_USER = smtp_username
# EMAIL_HOST_PASSWORD = smtp_password

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'