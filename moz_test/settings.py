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
SECRET_KEY = '!bfp0bh3cx7pu2bu4nq*q+=+npocl9y_i2ssb&xj_m)-83z+#n'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['lexis-test.srv.lrz.de', 'localhost']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'mozilla_django_oidc',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

AUTHENTICATION_BACKENDS = (
#https://buildmedia.readthedocs.org/media/pdf/mozilla-django-oidc/latest/mozilla-django-oidc.pdf
#1.2.2
#no, fix in keycloak ldap mapping
#    'mozilla_django_oidc.auth.OIDCAuthenticationBackend',
    'moz_test.keycloakauth.MyOIDCAB',
    # ...
)

OIDC_RP_CLIENT_ID = os.environ['OIDC_RP_CLIENT_ID']
OIDC_RP_CLIENT_SECRET = os.environ['OIDC_RP_CLIENT_SECRET']

#https://review.cloudera.org/r/13045/diff/1-2/#
OIDC_OP_AUTHORIZATION_ENDPOINT = "https://138.246.232.245:8443/auth/realms/rgh-test/protocol/openid-connect/auth"
OIDC_OP_TOKEN_ENDPOINT = "https://138.246.232.245:8443/auth/realms/rgh-test/protocol/openid-connect/token"
OIDC_OP_USER_ENDPOINT = "https://138.246.232.245:8443/auth/realms/rgh-test/protocol/openid-connect/userinfo"

OIDC_RP_SIGN_ALGO = "RS256"

OIDC_OP_JWKS_ENDPOINT = "https://138.246.232.245:8443/auth/realms/rgh-test/protocol/openid-connect/certs"

LOGIN_REDIRECT_URL = "https://lexis-test.srv.lrz.de/"
LOGOUT_REDIRECT_URL = "https://lexis-test.srv.lrz.de/"

OIDC_OP_LOGOUT_URL_METHOD = 'demo.views.provider_logout'

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

ROOT_URLCONF = 'moz_test.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['/home/rgarcia/webfrontend/lexis/django/mozilla/moz_test/demo/templates'],
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
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
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

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/home/rgarcia/webfrontend/lexis/django/mozilla/moz_test/debug.log',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
