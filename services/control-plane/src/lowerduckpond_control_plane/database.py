"""SQLAlchemy declarations shared by future control-plane models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for typed control-plane persistence models."""
