# task/utils.py
import logging
from typing import Any, Dict, Optional, Tuple, Union

from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import Notification, Task, Assignment 
from datetime import timedelta


logger = logging.getLogger(__name__)
User = get_user_model()


def format_datetime_friendly(dt) -> Optional[str]:
    """
    Format a (timezone-aware) datetime to: '23-Mar-2025 ~ 8:00 pm'
    - Uses timezone.localtime() so the result is in Django's current timezone.
    - Removes leading zero from hour and lowercases AM/PM.
    Returns None if dt is falsy.
    """
    if not dt:
        return None
    try:
        # convert to local timezone (safe for aware datetimes)
        local_dt = timezone.localtime(dt)
    except Exception:
        # fallback: use the original dt if conversion fails
        local_dt = dt

    # date part: 23-Mar-2025
    date_part = local_dt.strftime("%d-%b-%Y")

    # time part: '08:00 PM' -> '8:00 pm'
    time_part = local_dt.strftime("%I:%M %p").lstrip("0").lower()

    return f"{date_part} ~ {time_part}"

# Helper Functions for Notifications
def single_notification(
    recipient: Union[User, int, str], # pyright: ignore[reportInvalidTypeForm]
    title: str,
    message: str,
    type: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, int]:
    """
    Create a single notification for `recipient` which may be a User instance or a PK.
    Returns (success: bool, created_count: int)
    """
    try:
        meta_value = meta or {}

        # resolve recipient to User instance if necessary
        if not isinstance(recipient, User):
            try:
                recipient_user = User.objects.get(pk=int(recipient))
            except (ValueError, ObjectDoesNotExist) as exc:
                logger.exception("single_notification: recipient not found: %s", recipient)
                return False, 0
        else:
            recipient_user = recipient

        # Defer the DB write until after surrounding transaction commits
        def _create():
            try:
                Notification.objects.create(
                    recipient=recipient_user,
                    type=type,
                    title=(title or "")[:50],
                    message=message or "",
                    meta=meta_value,
                    read=False,
                )
                return True
            except Exception:
                logger.exception("single_notification: failed to create notification for user %s", getattr(recipient_user, "id", None))
                return False

        # If called inside a transaction ensure creation runs after commit
        try:
            transaction.on_commit(_create)
            # We optimistically return True here because creation is scheduled.
            # If you need synchronous confirmation, call _create() directly (but it's safer to defer).
            return True, 1
        except Exception:
            # fallback: try immediate creation (best-effort)
            ok = _create()
            return (True, 1) if ok else (False, 0)

    except Exception as exc:
        logger.exception("single_notification: unexpected error: %s", exc)
        return False, 0
  

def create_notification(
    task: Optional[Task] = None,
    title: str = "",
    message: str = "",
    type: str = "",
    recipient: Optional[str] = None,  # expected: "manager" or "member"
    meta: Optional[Dict[str, Any]] = None,
    admin: bool = False,
) -> Tuple[bool, int]:
    """
    Create notifications according to the new rules.

    - If admin=True:
        * Notify all Admins (role == User.Roles.ADMIN, is_active=True).
        * `task` and `recipient` are ignored.
    - If admin=False:
        * `task` is required.
        * `recipient` must be "member" or "manager".
            - "member": notify all members assigned to the task (active & approved).
            - "manager": notify task.created_by (if manager) and all Assignment.assigned_by (if manager),
               deduplicated and active.

    Returns:
        (success: bool, created_count: int)
    """
    try:
        meta_value = meta or {}

        with transaction.atomic():
            created_count = 0
            objs = []

            # ADMIN broadcast
            if admin:
                admins_qs = User.objects.filter(role=User.Roles.ADMIN, is_active=True)
                admins = list(admins_qs)
                if not admins:
                    logger.info("create_notification: no admins found to notify.")
                    return True, 0

                now = timezone.now()
                for adm in admins:
                    objs.append(
                        Notification(
                            recipient=adm,
                            type=type,
                            title=(title or "")[:50],
                            message=message or "",
                            meta=meta_value,
                            read=False,
                        )
                    )
                Notification.objects.bulk_create(objs)
                created_count = len(objs)
                return True, created_count

            # Non-admin path: task required
            if task is None:
                logger.error("create_notification: 'task' is required when admin=False.")
                return False, 0

            # Validate recipient
            if not recipient or recipient.lower() not in ("member", "manager"):
                logger.error("create_notification: invalid recipient '%s'. Must be 'member' or 'manager'.", recipient)
                return False, 0

            recipient_kind = recipient.lower()

            # MEMBER: all assigned members for the task
            if recipient_kind == "member":
                assignments = Assignment.objects.filter(task=task).select_related("user")
                members = []
                for a in assignments:
                    u = a.user
                    if not u:
                        continue
                    # only notify active & approved members
                    if getattr(u, "role", None) == User.Roles.MEMBER and getattr(u, "is_active", False) and getattr(u, "is_approved", False):
                        members.append(u)
                # deduplicate by id
                members_unique = {m.id: m for m in members}.values()
                if not members_unique:
                    logger.info("create_notification: no assigned members found for task %s", getattr(task, "id", None))
                    return True, 0

                for m in members_unique:
                    objs.append(
                        Notification(
                            recipient=m,
                            type=type,
                            title=(title or "")[:50],
                            message=message or "",
                            meta=meta_value,
                            read=False,
                        )
                    )
                Notification.objects.bulk_create(objs)
                created_count = len(objs)
                return True, created_count

            # MANAGER: task.created_by (if manager) + all assigned_by from assignments (if manager)
            if recipient_kind == "manager":
                managers_map = {}

                # include created_by if they are a manager and active
                creator = getattr(task, "created_by", None)
                if creator and getattr(creator, "role", None) == User.Roles.MANAGER and getattr(creator, "is_active", False) and getattr(creator, "is_approved", False):
                    managers_map[creator.id] = creator

                # include assigned_by from assignments
                assignments = Assignment.objects.filter(task=task).select_related("assigned_by")
                for a in assignments:
                    ab = getattr(a, "assigned_by", None)
                    if not ab:
                        continue
                    if getattr(ab, "role", None) == User.Roles.MANAGER and getattr(ab, "is_active", False) and getattr(ab, "is_approved", False):
                        managers_map[ab.id] = ab

                managers = list(managers_map.values())
                if not managers:
                    logger.info("create_notification: no managers involved for task %s", getattr(task, "id", None))
                    return True, 0

                for mgr in managers:
                    objs.append(
                        Notification(
                            recipient=mgr,
                            type=type,
                            title=(title or "")[:50],
                            message=message or "",
                            meta=meta_value,
                            read=False,
                        )
                    )
                Notification.objects.bulk_create(objs)
                created_count = len(objs)
                return True, created_count

            # shouldn't reach here
            logger.error("create_notification: unreachable branch reached (recipient=%s)", recipient)
            return False, 0

    except Exception as exc:
        logger.exception("create_notification: unexpected error: %s", exc)
        return False, 0


