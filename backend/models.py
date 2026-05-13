from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Float
from sqlalchemy import DateTime
from sqlalchemy import JSON

from datetime import datetime

from backend.database import Base

class Alert(Base):

    __tablename__ = "alerts"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    event = Column(String)

    severity = Column(String)

    ip = Column(String)

    user = Column(String)

    investigation = Column(String)

    mitre_attack = Column(String)

    predicted_next_attack = Column(String)

    confidence = Column(Float)

    raw_data = Column(JSON)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )