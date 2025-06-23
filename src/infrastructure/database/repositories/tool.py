"""
Tool System repositories for tool management and execution tracking.
"""

from uuid import UUID

from sqlalchemy import and_, desc, func, select
from sqlalchemy.orm import selectinload

from ..models.tool import MCPServer, Tool, ToolDefinition, ToolExecution
from .base import BaseRepository, TenantAwareRepository


class ToolRepository(TenantAwareRepository[Tool]):
    """Repository for tool management."""

    async def get_by_name(self, name: str, tenant_id: UUID) -> Tool | None:
        """Get tool by name within tenant."""
        result = await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.name == name,
                self.model.tenant_id == tenant_id
            ))
            .options(
                selectinload(self.model.creator),
                selectinload(self.model.definitions)
            )
        )
        return result.scalar_one_or_none()

    async def get_available_tools(
        self,
        tenant_id: UUID,
        user_id: UUID | None = None,
        category: str | None = None,
        tool_type: str | None = None,
        include_system: bool = True
    ) -> list[Tool]:
        """Get tools available to user/tenant."""
        filters = [
            self.model.is_active == True,
            (self.model.tenant_id == tenant_id) |
            (self.model.is_system_tool == True if include_system else False)
        ]

        if category:
            filters.append(self.model.category == category)

        if tool_type:
            filters.append(self.model.tool_type == tool_type)

        return await self.session.execute(
            select(self.model)
            .where(and_(*filters))
            .options(
                selectinload(self.model.creator),
                selectinload(self.model.definitions)
            )
            .order_by(self.model.name)
        ).scalars().all()

    async def get_system_tools(self) -> list[Tool]:
        """Get all system tools."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.is_system_tool == True,
                self.model.is_active == True
            ))
            .options(selectinload(self.model.definitions))
            .order_by(self.model.name)
        ).scalars().all()

    async def search_tools(
        self,
        query: str,
        tenant_id: UUID,
        limit: int = 20
    ) -> list[Tool]:
        """Search tools by name, display name, or description."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                (self.model.tenant_id == tenant_id) | (self.model.is_system_tool == True),
                self.model.is_active == True,
                (self.model.name.ilike(f'%{query}%') |
                 self.model.display_name.ilike(f'%{query}%') |
                 self.model.description.ilike(f'%{query}%'))
            ))
            .options(
                selectinload(self.model.creator),
                selectinload(self.model.definitions)
            )
            .order_by(desc(self.model.total_executions))
            .limit(limit)
        ).scalars().all()

    async def get_user_tools(
        self,
        user_id: UUID,
        tenant_id: UUID
    ) -> list[Tool]:
        """Get tools created by user."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.created_by == user_id,
                self.model.tenant_id == tenant_id
            ))
            .options(selectinload(self.model.definitions))
            .order_by(desc(self.model.created_at))
        ).scalars().all()

    async def update_usage_stats(
        self,
        tool_id: UUID,
        execution_successful: bool,
        execution_time_ms: int
    ) -> bool:
        """Update tool usage statistics."""
        tool = await self.get(tool_id)
        if not tool:
            return False

        tool.total_executions += 1
        if execution_successful:
            tool.successful_executions += 1

        # Update average execution time
        if tool.total_executions == 1:
            tool.average_execution_time = execution_time_ms
        else:
            tool.average_execution_time = (
                (tool.average_execution_time * (tool.total_executions - 1) + execution_time_ms) /
                tool.total_executions
            )

        await self.session.commit()
        return True


class ToolDefinitionRepository(BaseRepository[ToolDefinition]):
    """Repository for tool definitions."""

    async def get_current_definition(self, tool_id: UUID) -> ToolDefinition | None:
        """Get current definition for a tool."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.tool_id == tool_id,
                self.model.is_current == True
            ))
            .options(selectinload(self.model.mcp_server))
        ).scalar_one_or_none()

    async def get_definition_history(
        self,
        tool_id: UUID,
        limit: int = 10
    ) -> list[ToolDefinition]:
        """Get definition history for a tool."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.tool_id == tool_id)
            .order_by(desc(self.model.definition_version))
            .limit(limit)
        ).scalars().all()

    async def create_new_version(
        self,
        tool_id: UUID,
        schema_data: dict,
        execution_config: dict,
        version: str | None = None
    ) -> ToolDefinition:
        """Create new definition version and mark as current."""
        # Mark all existing definitions as not current
        await self.session.execute(
            select(self.model)
            .where(self.model.tool_id == tool_id)
            .update({"is_current": False})
        )

        # Generate version if not provided
        if not version:
            result = await self.session.execute(
                select(self.model.definition_version)
                .where(self.model.tool_id == tool_id)
                .order_by(desc(self.model.definition_version))
                .limit(1)
            )
            latest = result.scalar()

            if latest:
                # Simple version increment (e.g., "1.0.0" -> "1.0.1")
                parts = latest.split('.')
                parts[-1] = str(int(parts[-1]) + 1)
                version = '.'.join(parts)
            else:
                version = "1.0.0"

        # Create new definition
        new_definition = ToolDefinition(
            tool_id=tool_id,
            definition_version=version,
            is_current=True,
            input_schema=schema_data.get('input_schema', {}),
            output_schema=schema_data.get('output_schema', {}),
            execution_config=execution_config
        )

        return await self.create(new_definition)

    async def validate_definition(self, definition_id: UUID) -> bool:
        """Validate a tool definition."""
        definition = await self.get(definition_id)
        if not definition:
            return False

        # TODO: Implement actual validation logic
        # - Validate JSON schemas
        # - Check execution configuration
        # - Verify MCP server connectivity if applicable

        definition.is_valid = True
        definition.validation_errors = []
        await self.session.commit()
        return True


class MCPServerRepository(TenantAwareRepository[MCPServer]):
    """Repository for MCP server management."""

    async def get_by_name(self, name: str, tenant_id: UUID) -> MCPServer | None:
        """Get MCP server by name within tenant."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.name == name,
                self.model.tenant_id == tenant_id
            ))
            .options(selectinload(self.model.creator))
        ).scalar_one_or_none()

    async def get_active_servers(self, tenant_id: UUID) -> list[MCPServer]:
        """Get active MCP servers for tenant."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.tenant_id == tenant_id,
                self.model.is_active == True,
                self.model.health_status.in_(['healthy', 'degraded'])
            ))
            .options(selectinload(self.model.creator))
            .order_by(self.model.name)
        ).scalars().all()

    async def get_servers_by_type(
        self,
        server_type: str,
        tenant_id: UUID
    ) -> list[MCPServer]:
        """Get MCP servers by type."""
        return await self.session.execute(
            select(self.model)
            .where(and_(
                self.model.server_type == server_type,
                self.model.tenant_id == tenant_id,
                self.model.is_active == True
            ))
            .options(selectinload(self.model.creator))
        ).scalars().all()

    async def update_health_status(
        self,
        server_id: UUID,
        status: str,
        retry_count: int | None = None
    ) -> bool:
        """Update server health status."""
        server = await self.get(server_id)
        if not server:
            return False

        server.health_status = status
        if retry_count is not None:
            server.connection_retries = retry_count

        await self.session.commit()
        return True

    async def update_tools_info(
        self,
        server_id: UUID,
        available_tools: list[str],
        tool_schemas: dict
    ) -> bool:
        """Update server's available tools information."""
        server = await self.get(server_id)
        if not server:
            return False

        server.available_tools = available_tools
        server.tool_schemas = tool_schemas
        await self.session.commit()
        return True

    async def update_usage_stats(
        self,
        server_id: UUID,
        successful: bool,
        response_time_ms: int
    ) -> bool:
        """Update server usage statistics."""
        server = await self.get(server_id)
        if not server:
            return False

        server.total_requests += 1
        if successful:
            server.successful_requests += 1

        # Update average response time
        if server.total_requests == 1:
            server.average_response_time = response_time_ms
        else:
            server.average_response_time = (
                (server.average_response_time * (server.total_requests - 1) + response_time_ms) /
                server.total_requests
            )

        await self.session.commit()
        return True


class ToolExecutionRepository(BaseRepository[ToolExecution]):
    """Repository for tool execution tracking."""

    async def get_by_execution_id(self, execution_id: str) -> ToolExecution | None:
        """Get execution by execution ID."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.execution_id == execution_id)
            .options(
                selectinload(self.model.tool),
                selectinload(self.model.user),
                selectinload(self.model.conversation)
            )
        ).scalar_one_or_none()

    async def get_user_executions(
        self,
        user_id: UUID,
        limit: int = 50,
        offset: int = 0,
        status: str | None = None
    ) -> list[ToolExecution]:
        """Get user's tool executions."""
        filters = [self.model.user_id == user_id]

        if status:
            filters.append(self.model.status == status)

        return await self.session.execute(
            select(self.model)
            .where(and_(*filters))
            .options(selectinload(self.model.tool))
            .order_by(desc(self.model.started_at))
            .limit(limit)
            .offset(offset)
        ).scalars().all()

    async def get_tool_executions(
        self,
        tool_id: UUID,
        limit: int = 100,
        status: str | None = None
    ) -> list[ToolExecution]:
        """Get executions for a specific tool."""
        filters = [self.model.tool_id == tool_id]

        if status:
            filters.append(self.model.status == status)

        return await self.session.execute(
            select(self.model)
            .where(and_(*filters))
            .options(selectinload(self.model.user))
            .order_by(desc(self.model.started_at))
            .limit(limit)
        ).scalars().all()

    async def get_conversation_executions(
        self,
        conversation_id: UUID
    ) -> list[ToolExecution]:
        """Get tool executions for a conversation."""
        return await self.session.execute(
            select(self.model)
            .where(self.model.conversation_id == conversation_id)
            .options(
                selectinload(self.model.tool),
                selectinload(self.model.user)
            )
            .order_by(self.model.started_at)
        ).scalars().all()

    async def update_execution_status(
        self,
        execution_id: str,
        status: str,
        output_data: dict | None = None,
        error_data: dict | None = None,
        exit_code: int | None = None
    ) -> bool:
        """Update execution status and results."""
        execution = await self.get_by_execution_id(execution_id)
        if not execution:
            return False

        execution.status = status
        if output_data:
            execution.output_data = output_data
        if error_data:
            execution.error_data = error_data
        if exit_code is not None:
            execution.exit_code = exit_code

        if status in ['completed', 'failed', 'timeout']:
            from datetime import datetime
            execution.completed_at = datetime.utcnow()
            if execution.started_at:
                execution.duration_ms = int(
                    (execution.completed_at - execution.started_at).total_seconds() * 1000
                )

        await self.session.commit()
        return True

    async def get_execution_stats(
        self,
        tool_id: UUID | None = None,
        user_id: UUID | None = None,
        days: int = 30
    ) -> dict:
        """Get execution statistics."""
        from datetime import datetime, timedelta

        filters = [
            self.model.started_at >= datetime.utcnow() - timedelta(days=days)
        ]

        if tool_id:
            filters.append(self.model.tool_id == tool_id)
        if user_id:
            filters.append(self.model.user_id == user_id)

        result = await self.session.execute(
            select(
                func.count(self.model.id).label('total'),
                func.count(self.model.id).filter(self.model.status == 'completed').label('successful'),
                func.count(self.model.id).filter(self.model.status == 'failed').label('failed'),
                func.avg(self.model.duration_ms).label('avg_duration')
            ).where(and_(*filters))
        )
        result = result.first()

        return {
            'total_executions': result.total or 0,
            'successful_executions': result.successful or 0,
            'failed_executions': result.failed or 0,
            'success_rate': (result.successful / result.total * 100) if result.total > 0 else 0,
            'average_duration_ms': float(result.avg_duration or 0)
        }
