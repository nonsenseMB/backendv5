"""Add permission and role system

Revision ID: fab6d0110918
Revises: 4f9ecd6a89db
Create Date: 2025-06-24 12:58:58.819055

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fab6d0110918'
down_revision: Union[str, None] = '4f9ecd6a89db'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('permissions',
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('resource', sa.String(length=100), nullable=False),
    sa.Column('action', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('roles',
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('is_system', sa.Boolean(), nullable=True),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'name', name='_tenant_role_name_uc')
    )
    op.create_index(op.f('ix_roles_tenant_id'), 'roles', ['tenant_id'], unique=False)
    op.create_table('device_certificates',
    sa.Column('device_id', sa.UUID(), nullable=False),
    sa.Column('certificate', sa.Text(), nullable=False),
    sa.Column('certificate_chain', sa.Text(), nullable=True),
    sa.Column('serial_number', sa.String(length=255), nullable=False),
    sa.Column('fingerprint_sha256', sa.String(length=64), nullable=False),
    sa.Column('issuer_dn', sa.Text(), nullable=False),
    sa.Column('subject_dn', sa.Text(), nullable=False),
    sa.Column('common_name', sa.String(length=255), nullable=False),
    sa.Column('san_dns_names', sa.JSON(), nullable=True),
    sa.Column('san_ip_addresses', sa.JSON(), nullable=True),
    sa.Column('not_before', sa.DateTime(), nullable=False),
    sa.Column('not_after', sa.DateTime(), nullable=False),
    sa.Column('key_usage', sa.JSON(), nullable=True),
    sa.Column('extended_key_usage', sa.JSON(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('revoked', sa.Boolean(), nullable=True),
    sa.Column('revoked_at', sa.DateTime(), nullable=True),
    sa.Column('revocation_reason', sa.String(length=255), nullable=True),
    sa.Column('ocsp_url', sa.Text(), nullable=True),
    sa.Column('crl_distribution_points', sa.JSON(), nullable=True),
    sa.Column('last_ocsp_check', sa.DateTime(), nullable=True),
    sa.Column('last_crl_check', sa.DateTime(), nullable=True),
    sa.Column('is_trusted', sa.Boolean(), nullable=True),
    sa.Column('trust_chain_verified', sa.Boolean(), nullable=True),
    sa.Column('compliance_checked', sa.Boolean(), nullable=True),
    sa.Column('compliance_notes', sa.Text(), nullable=True),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['user_devices.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('fingerprint_sha256'),
    sa.UniqueConstraint('serial_number')
    )
    op.create_table('role_permissions',
    sa.Column('role_id', sa.UUID(), nullable=False),
    sa.Column('permission_id', sa.UUID(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('role_id', 'permission_id', name='_role_permission_uc')
    )
    op.create_table('user_roles',
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('role_id', sa.UUID(), nullable=False),
    sa.Column('granted_by', sa.UUID(), nullable=True),
    sa.Column('granted_at', sa.DateTime(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'role_id', 'tenant_id', name='_user_role_tenant_uc')
    )
    op.create_index(op.f('ix_user_roles_tenant_id'), 'user_roles', ['tenant_id'], unique=False)
    op.create_table('resource_permissions',
    sa.Column('resource_type', sa.String(length=50), nullable=False),
    sa.Column('resource_id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=True),
    sa.Column('team_id', sa.UUID(), nullable=True),
    sa.Column('permission', sa.String(length=50), nullable=False),
    sa.Column('granted_by', sa.UUID(), nullable=False),
    sa.Column('granted_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['granted_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('resource_type', 'resource_id', 'user_id', 'team_id', 'permission', 'tenant_id', name='_resource_permission_uc')
    )
    op.create_index(op.f('ix_resource_permissions_tenant_id'), 'resource_permissions', ['tenant_id'], unique=False)
    op.add_column('user_devices', sa.Column('sign_count', sa.Integer(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user_devices', 'sign_count')
    op.drop_index(op.f('ix_resource_permissions_tenant_id'), table_name='resource_permissions')
    op.drop_table('resource_permissions')
    op.drop_index(op.f('ix_user_roles_tenant_id'), table_name='user_roles')
    op.drop_table('user_roles')
    op.drop_table('role_permissions')
    op.drop_table('device_certificates')
    op.drop_index(op.f('ix_roles_tenant_id'), table_name='roles')
    op.drop_table('roles')
    op.drop_table('permissions')
    # ### end Alembic commands ###