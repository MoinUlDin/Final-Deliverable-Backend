# task/signals.py
import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db import transaction
from django.contrib.auth import get_user_model

from .models import Task, Assignment
from .utils import create_notification, single_notification, format_datetime_friendly

logger = logging.getLogger(__name__)
User = get_user_model()


@receiver(post_save, sender=Task)
def task_post_save_notify_admins(sender, instance: Task, created: bool, **kwargs):
    """
    When a Task is created, notify all admins if the creator is NOT an admin.
    We defer actual notification work to after transaction commit.
    """
    if not created:
        return

    try:
        creator = getattr(instance, "created_by", None)
        creator_is_admin = False
        if creator and getattr(creator, "role", None) == User.Roles.ADMIN:
            creator_is_admin = True

        if not creator_is_admin:
            title = f"New task created: {instance.title}"
            due_str = format_datetime_friendly(instance.due_date)
            if due_str:
                message = f"Task '{instance.title}' created, due on {due_str}."
            else:
                message = f"Task '{instance.title}' created."

            # Use your main creator to notify all admins
            def _notify_admins():
                create_notification(
                    task=None,
                    title=title,
                    message=message,
                    type="Task",
                    meta={"task_id": str(instance.id)},
                    admin=True,
                )

            # schedule after commit
            transaction.on_commit(_notify_admins)

    except Exception:
        logger.exception("task_post_save_notify_admins: error for task %s", getattr(instance, "id", None))


@receiver(post_save, sender=Assignment)
def assignment_post_save_notify_assignee(sender, instance: Assignment, created: bool, **kwargs):
    """
    When an Assignment is created, notify the single assigned user.
    Uses single_notification helper and defers actual DB write until transaction commit.
    """
    print('\n\n In assignemt Created \n\n')
    if not created:
        return
    print('\n\n In assignemt were Created now we will generate notification\n\n')
    try:
        assignee = instance.user
        task = instance.task

        if not assignee:
            return

        title = f"Assigned to: {task.title}"
        due_str = format_datetime_friendly(task.due_date)
        if due_str:
            message = f"You have been assigned to task '{task.title}' (due {due_str})."
        else:
            message = f"You have been assigned to task '{task.title}'."

        # schedule notification after DB commit
        def _notify_user():
            single_notification(
                recipient=assignee,
                title=title,
                message=message,
                type="Assignment",
                meta={"task_id": str(task.id), "assignment_id": str(instance.id)},
            )

        transaction.on_commit(_notify_user)

    except Exception:
        logger.exception("assignment_post_save_notify_assignee: error for assignment %s", getattr(instance, "id", None))
