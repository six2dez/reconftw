import os, secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = secrets.token_hex(32)

DEBUG = 1

ipAddress=os.popen('hostname -I | cut -d " " -f1').read().strip()
ALLOWED_HOSTS = [ipAddress, 'localhost', '127.0.0.1', '*']

# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True
# Application definition

INSTALLED_APPS = [
    'django_celery_beat',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'projects',
    'scans',
    'apikeys',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'web.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates'),],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
            # 'loaders': [
            #     ('django.template.loaders.cached.Loader', [
            #         'django.template.loaders.filesystem.Loader',
            #         'django.template.loaders.app_directories.Loader',
            #         ]),
            # ],
        },
    },
]

WSGI_APPLICATION = 'web.wsgi.application'

# DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440
DATA_UPLOAD_MAX_MEMORY_SIZE = 26214400
CACHE_MIDDLEWARE_SECONDS = 3600



# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

#DATABASES = {
#    'default': {
#        'ENGINE': 'django.db.backends.postgresql_psycopg2',
#        'NAME': 'web',
#        'USER': 'reconftw',
#        'PASSWORD': 'TorvaldS*12',
#        'HOST': 'localhost',
#        'PORT': '5432',
#    }
#}


# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators
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
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'America/Sao_Paulo'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_URL = 'static/'

#STATIC_ROOT = BASE_DIR/"static"

STATICFILES_DIRS = [
    BASE_DIR / "static",
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'projects:index'
LOGOUT_REDIRECT_URL = 'login'


# Celery Settings
CELERY_BROKER_URL = 'redis://localhost:6379'
CELERY_RESULT_BACKEND = 'redis://localhost:6379'
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CELERY_ROUTES = {
 'scans.tasks.run_scan': {'queue': 'run_scans'},
 'scans.tasks.new_scan_single_domain': {'queue': 'default'}
}

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': True,
#     'formatters': {
#         'standard': {
#             'format': '[%(levelname)s] %(asctime)-15s - %(message)s',
#             'datefmt': '%d/%b/%Y %H:%M:%S',
#         },
#         'color': {
#             '()': 'colorlog.ColoredFormatter',
#             'format':
#                 '%(log_color)s[%(levelname)s] %(asctime)-15s - %(message)s',
#             'datefmt': '%d/%b/%Y %H:%M:%S',
#             'log_colors': {
#                 'DEBUG': 'cyan',
#                 'INFO': 'green',
#                 'WARNING': 'yellow',
#                 'ERROR': 'red',
#                 'CRITICAL': 'red,bg_white',
#             },
#         },
#     },
#     'handlers': {
#         'logfile': {
#             'level': 'DEBUG',
#             'class': 'logging.FileHandler',
#             'filename': 'debug.log',
#             'formatter': 'standard',
#         },
#         'console': {
#             'level': 'DEBUG',
#             'class': 'logging.StreamHandler',
#             'formatter': 'color',
#         },
#     },
#     'loggers': {
#         'django': {
#             'handlers': ['console', 'logfile'],
#             'level': 'DEBUG',
#             'propagate': True,
#         },
#         'django.db.backends': {
#             'handlers': ['console', 'logfile'],
#             # DEBUG will log all queries, so change it to WARNING.
#             'level': 'INFO',
#             'propagate': False,   # Don't propagate to other handlers
#         },
#         'web.apikeys': {
#             'handlers': ['console', 'logfile'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#         'web.projects': {
#             'handlers': ['console', 'logfile'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#         'web.scans': {
#             'handlers': ['console', 'logfile'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#         'web.schedules': {
#             'handlers': ['console', 'logfile'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#         'web.web': {
#             'handlers': ['console', 'logfile'],
#             'level': 'DEBUG',
#             'propagate': False,
#         },
#     },
# }
