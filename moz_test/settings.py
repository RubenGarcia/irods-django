"""
Django settings for moz_test project.

Generated by 'django-admin startproject' using Django 1.11.21.

For more information on this file, see
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.11/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.11/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY ='GV.MZd:YU,sR@@d=8olZ@__m5bK=,=NgSoD/Z$bY/5#84;I[Md'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ['irods-api.lexis.lrz.de']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'mozilla_django_oidc',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'demo.apps.DemoConfig',
]

AUTH_USER_MODEL = 'demo.CustomUser'

AUTHENTICATION_BACKENDS = (
#https://buildmedia.readthedocs.org/media/pdf/mozilla-django-oidc/latest/mozilla-django-oidc.pdf
#1.2.2
#no, fix in keycloak ldap mapping
#    'mozilla_django_oidc.auth.OIDCAuthenticationBackend',
    'moz_test.keycloakauth.MyOIDCAB',
    # ...
)

OIDC_RP_CLIENT_ID = 'broker'
OIDC_RP_CLIENT_SECRET = 'ae93668d-48e0-40a5-a9a5-4df84e8629c5'

#https://review.cloudera.org/r/13045/diff/1-2/#
OIDC_OP_AUTHORIZATION_ENDPOINT = "https://keycloak.lrz.lexis-project.eu/auth/realms/portal-testing/protocol/openid-connect/auth"
OIDC_OP_TOKEN_ENDPOINT = "https://keycloak.lrz.lexis-project.eu/auth/realms/portal-testing/protocol/openid-connect/token"
OIDC_OP_USER_ENDPOINT = "https://keycloak.lrz.lexis-project.eu/auth/realms/portal-testing/protocol/openid-connect/userinfo"

KEYCLOAK_LOGOUT_ENDPOINT = "https://keycloak.lrz.lexis-project.eu/auth/realms/portal-testing/protocol/openid-connect/logout"

OIDC_RP_SIGN_ALGO = "RS256"

OIDC_OP_JWKS_ENDPOINT = "https://keycloak.lrz.lexis-project.eu/auth/realms/portal-testing/protocol/openid-connect/certs"

LOGIN_REDIRECT_URL = "https://irods-api.lexis.lrz.de/"
LOGOUT_REDIRECT_URL = "https://irods-api.lexis.lrz.de/"

LOGIN_URL = "https://irods-api.lexis.lrz.de/"

OIDC_OP_LOGOUT_URL_METHOD = 'demo.views.provider_logout'

OIDC_VERIFY_SSL = False

#rgh, while the use of this is discouraged, OIDC_STORE_ACCESS_TOKEN may be needed to have it available to send to irods
#rgh, since we cannot send to irods due to large size, disable this
#rgh, we need this if we are backend
OIDC_STORE_ACCESS_TOKEN=True
OIDC_STORE_ID_TOKEN=True

#https://github.com/heroku/heroku-django-template/issues/55
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'mozilla_django_oidc.middleware.SessionRefresh',
]

#OIDC_CREATE_USER = False

#rgh, did not make a difference in token size
#OIDC_RP_SCOPES = "openid"

ROOT_URLCONF = 'moz_test.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['./demo/templates'],
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

WSGI_APPLICATION = 'moz_test.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.11/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'irods_api',
        'USER': 'api',
        'PASSWORD': 'test_api_db_pw',
        'HOST': 'irods-postgresql.lexis.lrz.de',
        'PORT': '5432',
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.11/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/1.11/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.11/howto/static-files/

STATIC_URL = '/static/'
#STATICFILES_DIRS = [
#    os.path.join(BASE_DIR, 'static')
#]
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
	},
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'moz_test/debug.log',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
