"""Activity service — logging and querying user activity."""
from typing import Optional
from sqlalchemy.orm import Session
from app.models.activity import Activity


def log_activity(
    db: Session,
    user_id: int,
    activity_type: str,
    description: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    is_public: bool = True,
) -> Activity:
    """Record a user activity event.

    Args:
        db: Database session.
        user_id: The acting user.
        activity_type: One of ACTIVITY_TYPES (extensible).
        description: Human-readable description of what happened.
        target_type: Optional entity type (e.g. "blog_post", "comment").
        target_id: Optional entity ID (string for uuid compat).
        is_public: Whether this shows on the user's public profile.

    Returns:
        The created Activity instance.
    """
    activity = Activity(
        user_id=user_id,
        activity_type=activity_type,
        description=description,
        target_type=target_type,
        target_id=target_id,
        is_public=is_public,
    )
    db.add(activity)
    db.commit()
    db.refresh(activity)
    return activity


def get_user_activities(
    db: Session,
    user_id: int,
    public_only: bool = False,
    limit: int = 50,
) -> list[Activity]:
    """Get recent activities for a user.

    Args:
        db: Database session.
        user_id: Target user.
        public_only: If True, only return public activities (for profile views).
        limit: Max results.
    """
    query = db.query(Activity).filter(Activity.user_id == user_id)
    if public_only:
        query = query.filter(Activity.is_public == True)
    return query.order_by(Activity.created_at.desc()).limit(limit).all()


def get_recent_public_activities(db: Session, limit: int = 30) -> list[Activity]:
    """Get recent public activities across all users — for community feed."""
    return (
        db.query(Activity)
        .filter(Activity.is_public == True)
        .order_by(Activity.created_at.desc())
        .limit(limit)
        .all()
    )
