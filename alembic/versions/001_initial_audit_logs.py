"""Initial audit_logs table

Revision ID: 001
Revises: 
Create Date: 2026-01-07

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, index=True),
        
        # User information
        sa.Column('user_id', sa.String(255), nullable=False, index=True),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('user_role', sa.String(50), nullable=False, index=True),
        sa.Column('department', sa.String(255), nullable=True, index=True),
        
        # Request information
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('endpoint', sa.String(500), nullable=False),
        sa.Column('method', sa.String(10), nullable=False),
        sa.Column('request_size', sa.Integer(), default=0),
        sa.Column('response_size', sa.Integer(), default=0),
        sa.Column('response_time_ms', sa.Float(), default=0.0),
        sa.Column('status_code', sa.Integer(), default=200),
        
        # PII tracking
        sa.Column('pii_detected', sa.Boolean(), default=False, index=True),
        sa.Column('pii_types_found', postgresql.ARRAY(sa.String()), default=[]),
        sa.Column('pii_count', sa.Integer(), default=0),
        
        # Rate limiting
        sa.Column('rate_limit_remaining', sa.Integer(), nullable=True),
        
        # Metadata
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        
        # Violation tracking
        sa.Column('violation', sa.String(50), nullable=True, index=True),
        sa.Column('violation_details', sa.String(1000), nullable=True),
    )
    
    # Create indexes for common queries
    op.create_index('ix_audit_logs_user_role_timestamp', 'audit_logs', ['user_role', 'timestamp'])
    op.create_index('ix_audit_logs_department_timestamp', 'audit_logs', ['department', 'timestamp'])


def downgrade() -> None:
    op.drop_index('ix_audit_logs_department_timestamp', table_name='audit_logs')
    op.drop_index('ix_audit_logs_user_role_timestamp', table_name='audit_logs')
    op.drop_table('audit_logs')
