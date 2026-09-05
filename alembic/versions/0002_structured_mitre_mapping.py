"""Persist the version and evidence for structured ATT&CK mappings.

Revision ID: 0002_structured_mitre_mapping
Revises: 0001_canonical_incidents
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0002_structured_mitre_mapping"
down_revision = "0001_canonical_incidents"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "incidents",
        sa.Column("mitre_mapping_version", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "incidents",
        sa.Column("mitre_evidence", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("incidents", "mitre_evidence")
    op.drop_column("incidents", "mitre_mapping_version")
