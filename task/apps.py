# task/apps.py
import os
import logging
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)

class TaskConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'task'

    def ready(self):
        try:
            from . import signals  # noqa: F401
        except Exception:
            logger.exception("TaskConfig.ready: failed to import signals")
        # Only start scheduler when env var START_SCHEDULER=true (or DEBUG=False and an explicit flag)
        start_flag = os.environ.get("START_SCHEDULER", "false").lower() in ("1", "true", "yes")
        if not start_flag:
            logger.debug("TaskConfig.ready: START_SCHEDULER not set; not starting scheduler here.")
            return

        # still avoid autoreloader double-start in dev
        if settings.DEBUG and os.environ.get("RUN_MAIN") != "true":
            logger.debug("TaskConfig.ready: skipping scheduler start in autoreload parent process")
            return

        try:
            from .scheduler import schedule_jobs
            schedule_jobs()
        except Exception as exc:
            logger.exception("TaskConfig.ready: failed to start scheduler: %s", exc)