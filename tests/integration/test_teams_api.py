"""
Integration tests for Teams API.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.database.models.team import Team, TeamMember
from src.infrastructure.database.models.tenant import Tenant
from src.infrastructure.database.models.user import User


@pytest.mark.asyncio
async def test_create_team(
    authenticated_client: AsyncClient,
    test_user: User,
    test_tenant: Tenant,
    db_session: AsyncSession
):
    """Test creating a new team."""
    # Create team
    response = await authenticated_client.post(
        "/api/v1/teams",
        json={
            "name": "Engineering Team",
            "slug": "engineering",
            "description": "Backend development team"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    
    assert data["name"] == "Engineering Team"
    assert data["slug"] == "engineering"
    assert data["description"] == "Backend development team"
    assert data["member_count"] == 1
    assert data["is_active"] is True
    
    # Verify in database
    team = await db_session.get(Team, data["id"])
    assert team is not None
    assert team.name == "Engineering Team"
    assert team.created_by == test_user.id
    
    # Verify creator is owner
    member = await db_session.query(TeamMember).filter_by(
        team_id=team.id,
        user_id=test_user.id
    ).first()
    assert member is not None
    assert member.role == "owner"


@pytest.mark.asyncio
async def test_create_team_duplicate_slug(
    authenticated_client: AsyncClient,
    test_team: Team
):
    """Test creating team with duplicate slug fails."""
    response = await authenticated_client.post(
        "/api/v1/teams",
        json={
            "name": "Another Team",
            "slug": test_team.slug,
            "description": "Should fail"
        }
    )
    
    assert response.status_code == 409
    assert "already taken" in response.json()["detail"]


@pytest.mark.asyncio
async def test_list_user_teams(
    authenticated_client: AsyncClient,
    test_user: User,
    test_team: Team
):
    """Test listing user's teams."""
    response = await authenticated_client.get("/api/v1/teams")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["total"] >= 1
    assert any(team["id"] == str(test_team.id) for team in data["teams"])
    
    # Check user role is included
    team_data = next(t for t in data["teams"] if t["id"] == str(test_team.id))
    assert team_data["user_role"] == "owner"


@pytest.mark.asyncio
async def test_get_team_details(
    authenticated_client: AsyncClient,
    test_team: Team
):
    """Test getting team details."""
    response = await authenticated_client.get(f"/api/v1/teams/{test_team.id}")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["id"] == str(test_team.id)
    assert data["name"] == test_team.name
    assert "settings" in data
    assert "created_by" in data


@pytest.mark.asyncio
async def test_get_team_details_not_member(
    authenticated_client: AsyncClient,
    other_team: Team
):
    """Test getting team details when not a member."""
    response = await authenticated_client.get(f"/api/v1/teams/{other_team.id}")
    
    assert response.status_code == 403
    assert "not a member" in response.json()["detail"]


@pytest.mark.asyncio
async def test_update_team(
    authenticated_client: AsyncClient,
    test_team: Team
):
    """Test updating team details."""
    response = await authenticated_client.put(
        f"/api/v1/teams/{test_team.id}",
        json={
            "name": "Updated Team Name",
            "description": "Updated description"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["name"] == "Updated Team Name"
    assert data["description"] == "Updated description"


@pytest.mark.asyncio
async def test_update_team_not_admin(
    authenticated_client: AsyncClient,
    test_team_member: Team
):
    """Test updating team as non-admin fails."""
    response = await authenticated_client.put(
        f"/api/v1/teams/{test_team_member.id}",
        json={
            "name": "Should Fail"
        }
    )
    
    assert response.status_code == 403
    assert "Only admins" in response.json()["detail"]


@pytest.mark.asyncio
async def test_add_team_member(
    authenticated_client: AsyncClient,
    test_team: Team,
    other_user: User
):
    """Test adding a member to team."""
    response = await authenticated_client.post(
        f"/api/v1/teams/{test_team.id}/members",
        json={
            "user_id": str(other_user.id),
            "role": "member"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    
    assert data["user_id"] == str(other_user.id)
    assert data["role"] == "member"
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_list_team_members(
    authenticated_client: AsyncClient,
    test_team_with_members: Team
):
    """Test listing team members."""
    response = await authenticated_client.get(
        f"/api/v1/teams/{test_team_with_members.id}/members"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert len(data) >= 2  # Owner + at least one member
    
    # Check member details
    assert all("user" in member for member in data)
    assert all("role" in member for member in data)


@pytest.mark.asyncio
async def test_update_member_role(
    authenticated_client: AsyncClient,
    test_team_with_members: Team,
    team_member_user: User
):
    """Test updating a member's role."""
    response = await authenticated_client.put(
        f"/api/v1/teams/{test_team_with_members.id}/members/{team_member_user.id}",
        json={
            "role": "admin"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["role"] == "admin"


@pytest.mark.asyncio
async def test_remove_team_member(
    authenticated_client: AsyncClient,
    test_team_with_members: Team,
    team_member_user: User
):
    """Test removing a member from team."""
    response = await authenticated_client.delete(
        f"/api/v1/teams/{test_team_with_members.id}/members/{team_member_user.id}"
    )
    
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_remove_last_admin_fails(
    authenticated_client: AsyncClient,
    test_team: Team,
    test_user: User
):
    """Test removing last admin fails."""
    response = await authenticated_client.delete(
        f"/api/v1/teams/{test_team.id}/members/{test_user.id}"
    )
    
    assert response.status_code == 409
    assert "last admin" in response.json()["detail"]


@pytest.mark.asyncio
async def test_delete_team(
    authenticated_client: AsyncClient,
    test_team: Team
):
    """Test deleting a team."""
    response = await authenticated_client.delete(f"/api/v1/teams/{test_team.id}")
    
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_delete_team_not_owner(
    authenticated_client: AsyncClient,
    test_team_admin: Team
):
    """Test deleting team as non-owner fails."""
    response = await authenticated_client.delete(f"/api/v1/teams/{test_team_admin.id}")
    
    assert response.status_code == 403
    assert "Only team owner" in response.json()["detail"]