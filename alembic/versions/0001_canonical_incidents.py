"""Create the canonical incident schema and migrate legacy alert rows.

Revision ID: 0001_canonical_incidents
Revises:
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0001_canonical_incidents"
down_revision = None
branch_labels = None
depends_on = None


def _json_type(bind):
    if bind.dialect.name == "postgresql":
        return postgresql.JSONB(astext_type=sa.Text())
    return sa.JSON()


def _create_incidents(bind) -> None:
    json_type = _json_type(bind)
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("event", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("user", sa.String(length=255), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_method", sa.String(length=128), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=True),
        sa.Column("detection_metadata", json_type, nullable=True),
        sa.Column("investigation", sa.Text(), nullable=True),
        sa.Column("investigation_method", sa.String(length=128), nullable=True),
        sa.Column("predicted_next_attack", sa.String(length=255), nullable=True),
        sa.Column("prediction_confidence", sa.Float(), nullable=True),
        sa.Column("sequence_model_status", sa.String(length=128), nullable=True),
        sa.Column("investigation_metadata", json_type, nullable=True),
        sa.Column("mitre_technique_id", sa.String(length=32), nullable=True),
        sa.Column("mitre_technique_name", sa.String(length=255), nullable=True),
        sa.Column("mitre_tactic", sa.String(length=128), nullable=True),
        sa.Column("mitre_confidence", sa.Float(), nullable=True),
        sa.Column("recommended_action", sa.Text(), nullable=True),
        sa.Column("threat_intelligence_method", sa.String(length=128), nullable=True),
        sa.Column("threat_intelligence_metadata", json_type, nullable=True),
        sa.Column("telemetry", json_type, nullable=True),
        sa.Column("remediation_actions", json_type, nullable=True),
        sa.Column("remediation_metadata", json_type, nullable=True),
        sa.Column("reporting_metadata", json_type, nullable=True),
        sa.Column("stage_metadata", json_type, nullable=True),
        sa.Column("ground_truth", json_type, nullable=True),
        sa.Column("original_payload", json_type, nullable=True),
        sa.Column("current_stage", sa.String(length=64), nullable=False),
        sa.Column("processing_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processing_version", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_incidents"),
        sa.UniqueConstraint("event_id", name="uq_incidents_event_id"),
    )
    op.create_index("ix_incidents_incident_id", "incidents", ["incident_id"])
    op.create_index("ix_incidents_observed_at", "incidents", ["observed_at"])


def _migrate_postgresql_legacy_rows() -> None:
    op.execute(
        """
        WITH ranked AS (
            SELECT legacy.*,
                   row_number() OVER (
                       PARTITION BY COALESCE(
                           event_id,
                           md5(
                               COALESCE(event, '') || '|' ||
                               COALESCE(source_ip, ip, '') || '|' ||
                               COALESCE(timestamp::text, '')
                           )
                       )
                       ORDER BY
                           (reporting_metadata IS NOT NULL)::int DESC,
                           (remediation_metadata IS NOT NULL)::int DESC,
                           (threat_intelligence_metadata IS NOT NULL)::int DESC,
                           (investigation_metadata IS NOT NULL)::int DESC,
                           (investigation IS NOT NULL)::int DESC,
                           id DESC
                   ) AS logical_rank
            FROM soc_alerts AS legacy
        )
        INSERT INTO incidents (
            event_id, incident_id, schema_version, event, severity, source_ip,
            "user", observed_at, detection_method, anomaly_score,
            detection_metadata, investigation, investigation_method,
            predicted_next_attack, prediction_confidence,
            sequence_model_status, investigation_metadata,
            mitre_technique_id, mitre_technique_name, mitre_tactic,
            mitre_confidence, recommended_action,
            threat_intelligence_method, threat_intelligence_metadata,
            telemetry, remediation_actions, remediation_metadata,
            reporting_metadata, stage_metadata, ground_truth,
            original_payload, current_stage, processing_timestamp,
            processing_version, created_at, updated_at
        )
        SELECT
            COALESCE(event_id, gen_random_uuid()::text),
            COALESCE(incident_id, gen_random_uuid()::text),
            COALESCE(schema_version, 'legacy'),
            event,
            severity,
            COALESCE(source_ip, ip),
            "user",
            COALESCE(observed_at, timestamp, CURRENT_TIMESTAMP),
            COALESCE(detection_metadata->>'method', NULL),
            CASE
                WHEN detection_metadata->>'anomaly_score'
                     ~ '^-?[0-9]+([.][0-9]+)?$'
                THEN (detection_metadata->>'anomaly_score')::double precision
                ELSE NULL
            END,
            detection_metadata::jsonb,
            COALESCE(investigation_metadata->>'summary', investigation),
            COALESCE(investigation_metadata->>'method', investigation_method),
            COALESCE(
                investigation_metadata->>'predicted_next_attack',
                predicted_next_attack
            ),
            CASE
                WHEN COALESCE(investigation_metadata->>'confidence', confidence)
                     ~ '^-?[0-9]+([.][0-9]+)?$'
                THEN COALESCE(
                    investigation_metadata->>'confidence', confidence
                )::double precision
                ELSE NULL
            END,
            COALESCE(investigation_metadata->>'model_status', lstm_status),
            investigation_metadata::jsonb,
            CASE
                WHEN mitre_attack ~ '^T[0-9]{4}'
                THEN substring(mitre_attack FROM '^(T[0-9]{4}(?:[.][0-9]{3})?)')
                ELSE NULL
            END,
            CASE
                WHEN mitre_attack ~ '^T[0-9]{4}'
                THEN regexp_replace(
                    mitre_attack,
                    '^T[0-9]{4}(?:[.][0-9]{3})?[^A-Za-z0-9]*',
                    ''
                )
                ELSE mitre_attack
            END,
            threat_intelligence_metadata->>'mitre_tactic',
            CASE
                WHEN threat_intelligence_metadata->>'confidence'
                     ~ '^-?[0-9]+([.][0-9]+)?$'
                THEN (threat_intelligence_metadata->>'confidence')::double precision
                ELSE NULL
            END,
            threat_intelligence_metadata->>'recommended_action',
            threat_intelligence_metadata->>'method',
            threat_intelligence_metadata::jsonb,
            telemetry::jsonb,
            COALESCE(remediation_metadata::jsonb->'actions', '[]'::jsonb),
            remediation_metadata::jsonb,
            reporting_metadata::jsonb,
            stage_metadata::jsonb,
            ground_truth::jsonb,
            original_payload::jsonb,
            COALESCE(
                current_stage,
                CASE
                    WHEN reporting_metadata IS NOT NULL THEN 'reporting'
                    WHEN remediation_metadata IS NOT NULL THEN 'remediation'
                    WHEN threat_intelligence_metadata IS NOT NULL THEN 'threat_intel'
                    WHEN investigation_metadata IS NOT NULL OR investigation IS NOT NULL
                        THEN 'investigation'
                    WHEN detection_metadata IS NOT NULL THEN 'detection'
                    ELSE 'ingestion'
                END
            ),
            COALESCE(
                processing_timestamp,
                last_updated_at,
                observed_at,
                timestamp,
                CURRENT_TIMESTAMP
            ),
            COALESCE(processing_version, 'legacy-migration-v1'),
            COALESCE(observed_at, timestamp, CURRENT_TIMESTAMP),
            COALESCE(
                last_updated_at,
                processing_timestamp,
                observed_at,
                timestamp,
                CURRENT_TIMESTAMP
            )
        FROM ranked
        WHERE logical_rank = 1
        """
    )


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(inspect(bind).get_table_names())
    _create_incidents(bind)
    if "soc_alerts" in tables:
        if bind.dialect.name != "postgresql":
            raise RuntimeError(
                "Legacy soc_alerts migration is supported on PostgreSQL only"
            )
        _migrate_postgresql_legacy_rows()
        op.drop_table("soc_alerts")


def downgrade() -> None:
    op.drop_index("ix_incidents_observed_at", table_name="incidents")
    op.drop_index("ix_incidents_incident_id", table_name="incidents")
    op.drop_table("incidents")
