from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
import os
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)
# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-kjNJhk=4h53$sxmw1sj1f2u8_0_206&=875)*0)^l4b=!_y$gr7%ocg'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True


ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

# CORS settings
CORS_ALLOW_ALL_ORIGINS = True


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
    'task',
    'drf_spectacular',
    'rest_framework_simplejwt.token_blacklist',
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'rbac_vu.urls'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',  # keep for browsable API/admin if desired
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    # drf-spectacular schema generator
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),          # adjust
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),             # adjust
    'ROTATE_REFRESH_TOKENS': True,                          # issue a new refresh when /token/refresh/ is called
    'BLACKLIST_AFTER_ROTATION': True,                       # add old refresh tokens to blacklist after rotation
    'UPDATE_LAST_LOGIN': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,  # default, or use separate key
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),                       # "Bearer <token>"
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),

    # optional: add custom token classes or claims
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'RBAC-VU Task Management API',
    'DESCRIPTION': """
    Role Based Access Control System(RBAC)
    Created by: Moin Ul Din
    Email: BC200414690@vu.edu.pk
    ID: BC200414690
    """,
    'VERSION': '1.0.0',                      # change when you release a new API version
    'CONTACT': {
        'name': 'Moin Ul Din',
        'email': 'BC200414690@vu.edu.pk',
        # 'url': 'https://your-org.example.com',
    },
    'LICENSE': {
        'name': 'Virtual University of Pakistan',
        # 'url': 'https://opensource.org/licenses/MIT',
    },
    'TERMS_OF_SERVICE': 'https://example.com/terms/',

    # show the security scheme in OpenAPI so Swagger UI shows "Authorize"
    'SECURITY': [{'BearerAuth': []}],
    'SECURITY_SCHEMES': {
        'BearerAuth': {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
        }
    },

    # optional: servers list shown in the OpenAPI document
    'SERVERS': [
        {'url': 'http://localhost:8000', 'description': 'Local development'},
        # {'url': 'https://api.example.com', 'description': 'Production'}
    ],

    # other options...
    'SERVE_INCLUDE_SCHEMA': True,
}

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587                # use 587 + TLS, or 465 + SSL
EMAIL_USE_TLS = True            # STARTTLS
EMAIL_USE_SSL = False           # leave False when using TLS/587

EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")       # e.g. "your@gmail.com"
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")   # the App Password from Google
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", EMAIL_HOST_USER)


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'rbac_vu.wsgi.application'

AUTH_USER_MODEL = 'task.CustomUser'

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True



# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# User-uploaded files (images, attachments)
MEDIA_URL = "/user_pictures/"
MEDIA_ROOT = BASE_DIR