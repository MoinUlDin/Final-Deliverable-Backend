# task/scheduler.py
import logging
import os
import threading
from datetime import timedelta

from django_apscheduler.jobstores import DjangoJobStore, register_events
from apscheduler.schedulers.background import BackgroundScheduler
from django.utils import timezone

from .models import Task, Notification
from .utils import create_notification, format_datetime_friendly

logger = logging.getLogger(__name__)

# Module-level lock to ensure only one job executes DB writes at a time.
# APScheduler runs each job in its own thread, so this serializes jobs.
_job_lock = threading.Lock()


def _build_deadline_message(task, approaching=True):
    """
    Build a friendly notification message using format_datetime_friendly()
    approaching=True -> deadline approaching text
    approaching=False -> overdue text
    """
    due_str = format_datetime_friendly(task.due_date)
    if approaching:
        if due_str:
            return f"Task '{task.title}' is due on {due_str}. Please take necessary action."
        return f"Task '{task.title}' has an upcoming deadline. Please take necessary action."
    else:
        if due_str:
            return f"Task '{task.title}' was due on {due_str} and is now overdue. Please act immediately."
        return f"Task '{task.title}' is overdue. Please act immediately."


def notify_upcoming_deadlines():
    """
    Find tasks due tomorrow (date-only), not completed and not yet notified.
    Notify admins, managers involved, and assigned members. Set is_notified=True.
    This function acquires a module-level lock so it won't run concurrently with the other job.
    """
    logger.info("JOB START: notify_upcoming_deadlines")
    # serialize with other jobs
    with _job_lock:
        now = timezone.now()
        tomorrow_date = (now + timedelta(days=1)).date()

        qs = Task.objects.filter(
            due_date__date=tomorrow_date
        ).exclude(status=Task.Status.COMPLETED).filter(is_notified=False)

        if not qs.exists():
            logger.debug("notify_upcoming_deadlines: no tasks due tomorrow.")
            logger.info("JOB END: notify_upcoming_deadlines")
            return

        logger.info("notify_upcoming_deadlines: found %d task(s) due tomorrow", qs.count())
        for task in qs:
            try:
                title = f"Deadline approaching: {task.title}"
                message = _build_deadline_message(task, approaching=True)
                ntype = Notification.Types.DEADLINE if hasattr(Notification, "Types") else "Deadline"

                # Notify admins (broadcast)
                create_notification(
                    task=None,
                    title=title,
                    message=message,
                    type=ntype,
                    recipient=None,
                    meta={"task_id": str(task.id)},
                    admin=True,
                )

                # Notify managers involved
                create_notification(
                    task=task,
                    title=title,
                    message=message,
                    type=ntype,
                    recipient="manager",
                    meta={"task_id": str(task.id)},
                    admin=False,
                )

                # Notify assigned members
                create_notification(
                    task=task,
                    title=title,
                    message=message,
                    type=ntype,
                    recipient="member",
                    meta={"task_id": str(task.id)},
                    admin=False,
                )

                # mark task notified so we don't repeatedly notify
                task.is_notified = True
                task.save(update_fields=["is_notified"])

                logger.info("notify_upcoming_deadlines: notifications created for task %s", task.id)

            except Exception:
                # log and continue with next task
                logger.exception("notify_upcoming_deadlines: error handling task %s", getattr(task, "id", None))

    logger.info("JOB END: notify_upcoming_deadlines")


def notify_overdue_tasks():
    """
    Find tasks whose due_date < now (time-aware), not completed and not yet notified.
    Notify admins, managers involved, and assigned members. Set is_notified=True.
    This function acquires the same module-level lock to avoid concurrent DB writes.
    """
    logger.info("JOB START: notify_overdue_tasks")
    with _job_lock:
        now = timezone.now()

        qs = Task.objects.filter(
            due_date__lt=now
        ).exclude(status=Task.Status.COMPLETED).filter(is_notified=False)

        if not qs.exists():
            logger.debug("notify_overdue_tasks: no overdue tasks found.")
            logger.info("JOB END: notify_overdue_tasks")
            return

        logger.info("notify_overdue_tasks: found %d overdue task(s)", qs.count())
        for task in qs:
            try:
                title = f"Task overdue: {task.title}"
                message = _build_deadline_message(task, approaching=False)
                ntype = Notification.Types.DEADLINE if hasattr(Notification, "Types") else "Deadline"

                # admins
                create_notification(
                    task=None,
                    title=title,
                    message=message,
                    type=ntype,
                    recipient=None,
                    meta={"task_id": str(task.id)},
                    admin=True,
                )

                # managers
                create_notification(
                    task=task,
                    title=title,
                    message=message,
                    type=ntype,
                    recipient="manager",
                    meta={"task_id": str(task.id)},
                    admin=False,
                )

                # members
                create_notification(
                    task=task,
                    title=title,
                    message=message,
                    type=ntype,
                    recipient="member",
                    meta={"task_id": str(task.id)},
                    admin=False,
                    
                )

                # mark task as notified
                task.is_notified = True
                task.status = Task.Status.OVERDUE
                task.save(update_fields=["is_notified", 'status'])

                logger.info("notify_overdue_tasks: notifications created for task %s", task.id)

            except Exception:
                logger.exception("notify_overdue_tasks: error handling task %s", getattr(task, "id", None))

    logger.info("JOB END: notify_overdue_tasks")


def schedule_jobs():
    """
    Create scheduler, register jobstore, and add our interval jobs.
    Stagger the initial run of the second job by 2 seconds so they don't start at exactly the same time.
    """
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(DjangoJobStore(), "default")
    register_events(scheduler)

    now = timezone.now()

    # Add or replace jobs so we don't get duplicates on repeated starts
    scheduler.add_job(
        notify_upcoming_deadlines,
        trigger="interval",
        hours=8,
        id="notify_upcoming_deadlines",
        replace_existing=True,
        next_run_time=now,
        coalesce=True,
        max_instances=1,
    )

    # stagger the second job's initial run by 2 seconds to avoid exact simultaneous start
    scheduler.add_job(
        notify_overdue_tasks,
        trigger="interval",
        hours=9,
        id="notify_overdue_tasks",
        replace_existing=True,
        next_run_time=now + timedelta(seconds=2),
        coalesce=True,
        max_instances=1,
    )

    try:
        scheduler.start()
        logger.info("APScheduler started with jobs: notify_upcoming_deadlines (8h) and notify_overdue_tasks (9h)")
    except Exception:
        logger.exception("Failed to start APScheduler")
