"""
Agent repository implementation.
"""
from uuid import UUID

from sqlalchemy import and_, or_, select

from infrastructure.database.models.agent import Agent
from infrastructure.database.repositories.base import TenantAwareRepository


class AgentRepository(TenantAwareRepository[Agent]):
    """Repository for Agent model."""

    async def get_active_agents(
        self,
        skip: int = 0,
        limit: int = 100
    ) -> list[Agent]:
        """Get all active agents for the tenant."""
        return await self.get_multi(
            skip=skip,
            limit=limit,
            filters={'is_active': True},
            order_by='name'
        )

    async def get_by_name(self, name: str) -> Agent | None:
        """Get agent by name within the tenant."""
        stmt = select(Agent).where(
            and_(
                Agent.tenant_id == self.tenant_id,
                Agent.name == name
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_system_agents(self) -> list[Agent]:
        """Get all system agents for the tenant."""
        return await self.get_multi(
            filters={
                'is_system': True,
                'is_active': True
            }
        )

    async def search_agents(
        self,
        query: str,
        include_inactive: bool = False,
        limit: int = 20
    ) -> list[Agent]:
        """Search agents by name or description."""
        search_term = f"%{query}%"
        stmt = select(Agent).where(
            and_(
                Agent.tenant_id == self.tenant_id,
                or_(
                    Agent.name.ilike(search_term),
                    Agent.description.ilike(search_term)
                )
            )
        )

        if not include_inactive:
            stmt = stmt.where(Agent.is_active == True)

        stmt = stmt.limit(limit)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())


    async def update_graph_definition(
        self,
        agent_id: UUID,
        graph_definition: dict
    ) -> Agent | None:
        """Update agent graph definition."""
        return await self.update(agent_id, graph_definition=graph_definition)

    async def update_model_preferences(
        self,
        agent_id: UUID,
        model_preferences: dict
    ) -> Agent | None:
        """Update agent model preferences."""
        return await self.update(agent_id, model_preferences=model_preferences)

    async def activate_agent(self, agent_id: UUID) -> Agent | None:
        """Activate an agent."""
        return await self.update(agent_id, is_active=True)

    async def deactivate_agent(self, agent_id: UUID) -> Agent | None:
        """Deactivate an agent."""
        return await self.update(agent_id, is_active=False)

    async def is_name_available(self, name: str) -> bool:
        """Check if an agent name is available within the tenant."""
        existing = await self.get_by_name(name)
        return existing is None
