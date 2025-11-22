# task/signals.py
import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db import transaction
from django.contrib.auth import get_user_model

from .models import Task, Assignment, Comment
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


@receiver(post_save, sender=Comment)
def notify_on_comment(sender, instance: Comment, created, **kwargs):
    """
    When a new comment is created:
      - If it's a reply -> notify parent comment owner (unless author)
      - Notify task.created_by (if manager/admin and not author)
      - Notify all Assignment.user (assignees) except author
      - Notify all Assignment.assigned_by (managers who assigned) except author
    Deduplicates recipients and never notifies the comment author.
    """
    if not created:
        return

    try:
        comment = instance
        task = comment.task
        author = comment.created_by

        # use set of ints (user ids) to deduplicate
        recipient_ids = set()

        # 1) Parent owner (reply case)
        if comment.parent and getattr(comment.parent, "created_by", None):
            p_owner = comment.parent.created_by
            if p_owner and p_owner.id != getattr(author, "id", None):
                recipient_ids.add(p_owner.id)

        # 2) Task creator (if not the author)
        if getattr(task, "created_by", None) and task.created_by.id != getattr(author, "id", None):
            recipient_ids.add(task.created_by.id)

        # 3) Assignments — gather assignees and assigned_by
        assignments = Assignment.objects.filter(task=task).select_related("user", "assigned_by")

        for a in assignments:
            # assignee (member)
            if getattr(a, "user", None) and a.user.id != getattr(author, "id", None):
                recipient_ids.add(a.user.id)

            # assigned_by (manager) — assigned_by may be null
            if getattr(a, "assigned_by", None) and a.assigned_by.id != getattr(author, "id", None):
                recipient_ids.add(a.assigned_by.id)

        # final defensive remove of author (in case present)
        if getattr(author, "id", None) in recipient_ids:
            recipient_ids.discard(author.id)

        if not recipient_ids:
            logger.debug("notify_on_comment: no recipients (only author or no participants).")
            return

        # Build title + message. For recipients we can tailor message for parent-owner vs others.
        base_title = f"comment on: {task.title}"
        # Keep message short; frontend can use meta (task_id/comment_id) to show details
        comment_preview = (comment.text or "")[:180]

        # iterate recipients and send notification
        for uid in recipient_ids:
            try:
                # If this recipient is parent owner, give a more specific message
                is_parent_owner = bool(comment.parent and comment.parent.created_by and comment.parent.created_by.id == uid)
                if is_parent_owner:
                    message = f"@{author.get_full_name() or author.username} replied to your comment on task '{task.title}': \"{comment_preview}\""
                else:
                    message = f"@{author.get_full_name() or author.username} commented on task '{task.title}': \"{comment_preview}\""


                single_notification(
                    recipient=uid,
                    title=base_title,
                    message=message,
                    type="Comment",
                    meta={
                        "task_id": str(task.id),
                        "comment_id": str(comment.id),
                        "parent_id": str(comment.parent.id) if comment.parent else None,
                    },
                )
            except Exception:
                logger.exception("notify_on_comment: failed to queue notification for user %s", uid)

    except Exception:
        logger.exception("notify_on_comment: unexpected error")

            
