# Task 009: Integration Test Suite

## Priority: MEDIUM
**Estimated Time**: 6-7 hours  
**Dependencies**: Tasks 001-008 (All unit and specialized tests)  
**Blocking**: End-to-end confidence

## Why This Task is Critical

Integration tests verify:
1. **Component interactions** - Systems work together correctly
2. **Data flow** - Information passes between layers properly
3. **Transaction boundaries** - Data consistency is maintained
4. **External integrations** - Third-party services work correctly
5. **Real-world scenarios** - Complete user workflows function

## What Needs to Be Done

### 1. API Integration Tests

Create `tests/integration/test_document_api_flow.py`:
```python
"""Test complete document API workflows."""
import pytest
from httpx import AsyncClient
from datetime import datetime
from tests.factories import UserFactory, TeamFactory

class TestDocumentAPIFlow:
    """Test document operations through API."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_complete_document_lifecycle(self, async_client: AsyncClient, test_user):
        """Test creating, updating, sharing, and deleting a document."""
        headers = create_auth_headers(test_user)
        
        # 1. Create document
        create_response = await async_client.post(
            "/api/v1/documents",
            headers=headers,
            json={
                "title": "Integration Test Document",
                "content": {
                    "type": "doc",
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": "This is a test document"}
                            ]
                        }
                    ]
                },
                "tags": ["test", "integration"]
            }
        )
        assert create_response.status_code == 201
        document = create_response.json()
        doc_id = document["id"]
        
        # 2. Read document
        read_response = await async_client.get(
            f"/api/v1/documents/{doc_id}",
            headers=headers
        )
        assert read_response.status_code == 200
        assert read_response.json()["title"] == "Integration Test Document"
        
        # 3. Update document
        update_response = await async_client.patch(
            f"/api/v1/documents/{doc_id}",
            headers=headers,
            json={
                "title": "Updated Integration Test",
                "status": "published"
            }
        )
        assert update_response.status_code == 200
        assert update_response.json()["status"] == "published"
        
        # 4. Share document
        share_response = await async_client.post(
            f"/api/v1/documents/{doc_id}/share",
            headers=headers,
            json={
                "expires_in_hours": 24,
                "permissions": ["read"]
            }
        )
        assert share_response.status_code == 201
        share_token = share_response.json()["token"]
        
        # 5. Access shared document (no auth)
        shared_response = await async_client.get(
            f"/api/v1/shared/{share_token}"
        )
        assert shared_response.status_code == 200
        assert shared_response.json()["title"] == "Updated Integration Test"
        
        # 6. Add collaborator
        collaborator = await UserFactory.create(tenant_id=test_user.tenant_id)
        permission_response = await async_client.post(
            f"/api/v1/documents/{doc_id}/permissions",
            headers=headers,
            json={
                "user_id": str(collaborator.id),
                "permission": "write"
            }
        )
        assert permission_response.status_code == 201
        
        # 7. Verify collaborator access
        collab_headers = create_auth_headers(collaborator)
        collab_response = await async_client.get(
            f"/api/v1/documents/{doc_id}",
            headers=collab_headers
        )
        assert collab_response.status_code == 200
        
        # 8. Delete document
        delete_response = await async_client.delete(
            f"/api/v1/documents/{doc_id}",
            headers=headers
        )
        assert delete_response.status_code == 204
        
        # 9. Verify deletion
        deleted_response = await async_client.get(
            f"/api/v1/documents/{doc_id}",
            headers=headers
        )
        assert deleted_response.status_code == 404
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_document_versioning_flow(self, async_client: AsyncClient, test_user):
        """Test document version management."""
        headers = create_auth_headers(test_user)
        
        # Create document
        create_resp = await async_client.post(
            "/api/v1/documents",
            headers=headers,
            json={"title": "Versioned Document", "content": {"text": "v1"}}
        )
        doc_id = create_resp.json()["id"]
        
        # Make multiple edits
        versions = []
        for i in range(5):
            update_resp = await async_client.patch(
                f"/api/v1/documents/{doc_id}",
                headers=headers,
                json={
                    "content": {"text": f"Version {i+2}"},
                    "change_description": f"Update {i+1}"
                }
            )
            versions.append(update_resp.json()["version"])
        
        # Get version history
        history_resp = await async_client.get(
            f"/api/v1/documents/{doc_id}/versions",
            headers=headers
        )
        assert history_resp.status_code == 200
        history = history_resp.json()
        assert len(history) == 6  # Original + 5 updates
        
        # Restore old version
        restore_resp = await async_client.post(
            f"/api/v1/documents/{doc_id}/versions/3/restore",
            headers=headers
        )
        assert restore_resp.status_code == 200
        
        # Verify restoration
        current_resp = await async_client.get(
            f"/api/v1/documents/{doc_id}",
            headers=headers
        )
        assert "Version 3" in str(current_resp.json()["content"])
```

### 2. Knowledge Graph Integration Tests

Create `tests/integration/test_knowledge_graph_flow.py`:
```python
"""Test knowledge graph complete workflows."""
import pytest
import numpy as np
from tests.utils import create_test_embedding

class TestKnowledgeGraphFlow:
    """Test knowledge graph operations end-to-end."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_document_to_knowledge_extraction(self, async_client, test_user):
        """Test extracting knowledge from documents."""
        headers = create_auth_headers(test_user)
        
        # 1. Create knowledge base
        kb_response = await async_client.post(
            "/api/v1/knowledge-bases",
            headers=headers,
            json={
                "name": "Test Knowledge Base",
                "description": "Integration test KB",
                "vector_store": "milvus",
                "embedding_model": "openai-ada-002"
            }
        )
        assert kb_response.status_code == 201
        kb_id = kb_response.json()["id"]
        
        # 2. Create document with rich content
        doc_response = await async_client.post(
            "/api/v1/documents",
            headers=headers,
            json={
                "title": "Company Overview",
                "content": {
                    "text": """
                    Acme Corporation was founded in 2020 by John Smith and Jane Doe.
                    The company is headquartered in San Francisco and specializes in
                    artificial intelligence solutions. Their main product, AcmeAI,
                    serves over 1000 enterprise customers worldwide.
                    """
                }
            }
        )
        doc_id = doc_response.json()["id"]
        
        # 3. Process document into knowledge base
        process_response = await async_client.post(
            f"/api/v1/knowledge-bases/{kb_id}/documents",
            headers=headers,
            json={"document_id": doc_id}
        )
        assert process_response.status_code == 202  # Accepted for processing
        job_id = process_response.json()["job_id"]
        
        # 4. Wait for processing (with timeout)
        await wait_for_job_completion(async_client, job_id, headers)
        
        # 5. Verify entities were extracted
        entities_response = await async_client.get(
            f"/api/v1/knowledge-bases/{kb_id}/entities",
            headers=headers
        )
        entities = entities_response.json()["items"]
        
        # Should have extracted entities
        entity_names = [e["name"] for e in entities]
        assert "Acme Corporation" in entity_names
        assert "John Smith" in entity_names
        assert "Jane Doe" in entity_names
        assert "San Francisco" in entity_names
        
        # 6. Verify relationships
        relations_response = await async_client.get(
            f"/api/v1/knowledge-bases/{kb_id}/relations",
            headers=headers
        )
        relations = relations_response.json()["items"]
        
        # Should have relationships
        relation_types = [r["type"] for r in relations]
        assert "founded_by" in relation_types
        assert "headquartered_in" in relation_types
        
        # 7. Test semantic search
        search_response = await async_client.post(
            f"/api/v1/knowledge-bases/{kb_id}/search",
            headers=headers,
            json={
                "query": "Who founded the company?",
                "top_k": 5
            }
        )
        results = search_response.json()["results"]
        assert len(results) > 0
        assert any("John Smith" in str(r) for r in results)
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_knowledge_graph_queries(self, async_client, test_user, test_kb):
        """Test complex knowledge graph queries."""
        headers = create_auth_headers(test_user)
        
        # Setup: Create interconnected entities
        entities = await create_test_knowledge_graph(test_kb.id)
        
        # 1. Find paths between entities
        path_response = await async_client.post(
            f"/api/v1/knowledge-bases/{test_kb.id}/graph/paths",
            headers=headers,
            json={
                "source_entity_id": str(entities["person1"].id),
                "target_entity_id": str(entities["company2"].id),
                "max_depth": 3
            }
        )
        paths = path_response.json()["paths"]
        assert len(paths) > 0
        
        # 2. Get entity neighborhood
        neighbors_response = await async_client.get(
            f"/api/v1/knowledge-bases/{test_kb.id}/entities/{entities['person1'].id}/neighbors",
            headers=headers,
            params={"depth": 2}
        )
        neighbors = neighbors_response.json()["entities"]
        assert len(neighbors) >= 3
        
        # 3. Find similar entities
        similar_response = await async_client.post(
            f"/api/v1/knowledge-bases/{test_kb.id}/entities/similar",
            headers=headers,
            json={
                "entity_id": str(entities["company1"].id),
                "limit": 5
            }
        )
        similar = similar_response.json()["entities"]
        assert entities["company2"].id in [e["id"] for e in similar]
```

### 3. Tool System Integration Tests

Create `tests/integration/test_tool_system_flow.py`:
```python
"""Test tool system complete workflows."""
import pytest
import asyncio
from tests.utils import wait_for_condition

class TestToolSystemFlow:
    """Test tool creation, discovery, and execution."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_tool_creation_and_execution(self, async_client, test_user):
        """Test creating and executing custom tools."""
        headers = create_auth_headers(test_user)
        
        # 1. Create custom tool
        tool_response = await async_client.post(
            "/api/v1/tools",
            headers=headers,
            json={
                "name": "text-analyzer",
                "display_name": "Text Analyzer",
                "description": "Analyzes text for various metrics",
                "category": "text-processing",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"},
                        "metrics": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["length", "words", "sentiment"]}
                        }
                    },
                    "required": ["text", "metrics"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "results": {"type": "object"}
                    }
                }
            }
        )
        assert tool_response.status_code == 201
        tool_id = tool_response.json()["id"]
        
        # 2. Create tool implementation
        impl_response = await async_client.post(
            f"/api/v1/tools/{tool_id}/implementation",
            headers=headers,
            json={
                "runtime": "python",
                "code": """
def execute(input_data):
    text = input_data['text']
    metrics = input_data['metrics']
    results = {}
    
    if 'length' in metrics:
        results['length'] = len(text)
    if 'words' in metrics:
        results['words'] = len(text.split())
    if 'sentiment' in metrics:
        # Simple sentiment (real implementation would use ML)
        results['sentiment'] = 'positive' if 'good' in text.lower() else 'neutral'
    
    return {'results': results}
                """
            }
        )
        assert impl_response.status_code == 201
        
        # 3. Execute tool
        exec_response = await async_client.post(
            f"/api/v1/tools/{tool_id}/execute",
            headers=headers,
            json={
                "input": {
                    "text": "This is a good example of integration testing",
                    "metrics": ["length", "words", "sentiment"]
                }
            }
        )
        assert exec_response.status_code == 200
        execution = exec_response.json()
        
        # Verify results
        results = execution["output"]["results"]
        assert results["length"] == 45
        assert results["words"] == 8
        assert results["sentiment"] == "positive"
        
        # 4. Check execution history
        history_response = await async_client.get(
            f"/api/v1/tools/{tool_id}/executions",
            headers=headers
        )
        executions = history_response.json()["items"]
        assert len(executions) == 1
        assert executions[0]["status"] == "completed"
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_mcp_server_integration(self, async_client, test_user):
        """Test MCP server discovery and tool usage."""
        headers = create_auth_headers(test_user)
        
        # 1. Register MCP server
        server_response = await async_client.post(
            "/api/v1/mcp-servers",
            headers=headers,
            json={
                "name": "test-mcp-server",
                "connection_type": "http",
                "connection_config": {
                    "url": "http://localhost:8888/mcp"
                }
            }
        )
        server_id = server_response.json()["id"]
        
        # 2. Discover tools from MCP
        discover_response = await async_client.post(
            f"/api/v1/mcp-servers/{server_id}/discover",
            headers=headers
        )
        discovered_tools = discover_response.json()["tools"]
        assert len(discovered_tools) > 0
        
        # 3. Import discovered tool
        import_response = await async_client.post(
            f"/api/v1/mcp-servers/{server_id}/tools/import",
            headers=headers,
            json={
                "tool_names": [discovered_tools[0]["name"]]
            }
        )
        imported = import_response.json()["imported"]
        assert len(imported) == 1
        
        # 4. Execute MCP tool
        mcp_tool_id = imported[0]["id"]
        exec_response = await async_client.post(
            f"/api/v1/tools/{mcp_tool_id}/execute",
            headers=headers,
            json={
                "input": discovered_tools[0]["example_input"]
            }
        )
        assert exec_response.status_code == 200
```

### 4. Multi-System Integration Tests

Create `tests/integration/test_multi_system_flow.py`:
```python
"""Test interactions between multiple systems."""
import pytest

class TestMultiSystemIntegration:
    """Test complex workflows across systems."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_document_tool_knowledge_flow(self, async_client, test_user):
        """Test workflow: Document → Tool Processing → Knowledge Graph."""
        headers = create_auth_headers(test_user)
        
        # 1. Create document
        doc = await create_test_document(
            async_client,
            headers,
            content="Apple Inc. released the iPhone in 2007. Steve Jobs was the CEO."
        )
        
        # 2. Create entity extraction tool
        tool = await create_entity_extraction_tool(async_client, headers)
        
        # 3. Process document with tool
        tool_result = await execute_tool(
            async_client,
            headers,
            tool["id"],
            {"document_id": doc["id"]}
        )
        
        entities = tool_result["output"]["entities"]
        assert "Apple Inc." in [e["name"] for e in entities]
        assert "Steve Jobs" in [e["name"] for e in entities]
        
        # 4. Create knowledge base
        kb = await create_knowledge_base(async_client, headers)
        
        # 5. Import tool results to knowledge graph
        import_response = await async_client.post(
            f"/api/v1/knowledge-bases/{kb['id']}/import",
            headers=headers,
            json={
                "source": "tool_output",
                "tool_execution_id": tool_result["execution_id"],
                "mapping": {
                    "entities": "output.entities",
                    "relations": "output.relations"
                }
            }
        )
        assert import_response.status_code == 202
        
        # 6. Query knowledge graph
        await wait_for_job_completion(
            async_client,
            import_response.json()["job_id"],
            headers
        )
        
        # Search for Steve Jobs
        search_results = await search_knowledge_base(
            async_client,
            headers,
            kb["id"],
            "Steve Jobs CEO"
        )
        
        assert len(search_results) > 0
        assert any("Apple" in str(r) for r in search_results)
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_team_collaboration_flow(self, async_client, test_team):
        """Test team collaboration features."""
        # Create team members
        members = await create_team_members(test_team, count=3)
        member_headers = [create_auth_headers(m) for m in members]
        
        # 1. Member 1 creates document
        doc = await async_client.post(
            "/api/v1/documents",
            headers=member_headers[0],
            json={
                "title": "Team Project",
                "team_id": str(test_team.id)
            }
        )
        doc_id = doc.json()["id"]
        
        # 2. Member 2 edits document
        await async_client.patch(
            f"/api/v1/documents/{doc_id}",
            headers=member_headers[1],
            json={"content": {"text": "Member 2 contribution"}}
        )
        
        # 3. Member 3 adds comment
        comment_resp = await async_client.post(
            f"/api/v1/documents/{doc_id}/comments",
            headers=member_headers[2],
            json={"text": "Great work team!"}
        )
        
        # 4. Check activity feed
        activity_resp = await async_client.get(
            f"/api/v1/teams/{test_team.id}/activity",
            headers=member_headers[0]
        )
        activities = activity_resp.json()["items"]
        
        # Should see all team activities
        activity_types = [a["type"] for a in activities]
        assert "document_created" in activity_types
        assert "document_edited" in activity_types
        assert "comment_added" in activity_types
```

### 5. WebSocket Integration Tests

Create `tests/integration/test_websocket_flow.py`:
```python
"""Test WebSocket real-time features."""
import pytest
import websockets
import json

class TestWebSocketIntegration:
    """Test real-time collaboration via WebSocket."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_realtime_document_collaboration(self, test_document, test_users):
        """Test real-time document editing."""
        user1, user2 = test_users[:2]
        doc_id = test_document.id
        
        # Connect both users via WebSocket
        ws1 = await connect_websocket(user1, f"/ws/documents/{doc_id}")
        ws2 = await connect_websocket(user2, f"/ws/documents/{doc_id}")
        
        try:
            # User 1 sends edit
            await ws1.send(json.dumps({
                "type": "edit",
                "data": {
                    "path": ["content", "text"],
                    "value": "User 1 edit"
                }
            }))
            
            # User 2 should receive update
            message = await asyncio.wait_for(ws2.recv(), timeout=1.0)
            update = json.loads(message)
            
            assert update["type"] == "document_updated"
            assert update["user_id"] == str(user1.id)
            assert "User 1 edit" in str(update["changes"])
            
            # Test presence
            await ws1.send(json.dumps({"type": "presence", "data": {"cursor": 10}}))
            
            presence_msg = await asyncio.wait_for(ws2.recv(), timeout=1.0)
            presence = json.loads(presence_msg)
            
            assert presence["type"] == "user_presence"
            assert presence["user_id"] == str(user1.id)
            assert presence["data"]["cursor"] == 10
            
        finally:
            await ws1.close()
            await ws2.close()
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_websocket_reconnection(self, test_user, test_document):
        """Test WebSocket reconnection handling."""
        ws = await connect_websocket(test_user, f"/ws/documents/{test_document.id}")
        
        # Simulate disconnect
        await ws.close()
        
        # Reconnect with last event ID
        ws_reconnect = await connect_websocket(
            test_user,
            f"/ws/documents/{test_document.id}",
            headers={"Last-Event-ID": "12345"}
        )
        
        # Should receive missed events
        message = await asyncio.wait_for(ws_reconnect.recv(), timeout=1.0)
        recovery = json.loads(message)
        
        assert recovery["type"] == "recovery"
        assert "missed_events" in recovery
        
        await ws_reconnect.close()
```

### 6. End-to-End User Journey Tests

Create `tests/integration/test_user_journeys.py`:
```python
"""Test complete user journeys."""
import pytest

class TestUserJourneys:
    """Test realistic user workflows."""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_new_user_onboarding(self, async_client):
        """Test complete new user onboarding flow."""
        # 1. User signs up
        signup_resp = await async_client.post(
            "/api/v1/auth/signup",
            json={
                "email": "newuser@example.com",
                "name": "New User",
                "company": "Test Corp"
            }
        )
        assert signup_resp.status_code == 201
        user_data = signup_resp.json()
        
        # 2. Verify email (simulate)
        verify_resp = await async_client.post(
            "/api/v1/auth/verify-email",
            json={
                "token": user_data["verification_token"]
            }
        )
        assert verify_resp.status_code == 200
        
        # 3. Complete profile
        headers = create_auth_headers_from_response(verify_resp)
        profile_resp = await async_client.patch(
            "/api/v1/users/me",
            headers=headers,
            json={
                "timezone": "America/New_York",
                "preferences": {
                    "theme": "dark",
                    "language": "en"
                }
            }
        )
        assert profile_resp.status_code == 200
        
        # 4. Create first document
        doc_resp = await async_client.post(
            "/api/v1/documents",
            headers=headers,
            json={
                "title": "My First Document",
                "content": {"text": "Getting started!"}
            }
        )
        assert doc_resp.status_code == 201
        
        # 5. Explore features
        # - Create knowledge base
        kb_resp = await async_client.post(
            "/api/v1/knowledge-bases",
            headers=headers,
            json={"name": "My Knowledge"}
        )
        assert kb_resp.status_code == 201
        
        # - Browse tools
        tools_resp = await async_client.get(
            "/api/v1/tools",
            headers=headers
        )
        assert tools_resp.status_code == 200
        assert len(tools_resp.json()["items"]) > 0
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_power_user_workflow(self, async_client, power_user):
        """Test advanced user workflow."""
        headers = create_auth_headers(power_user)
        
        # Complex workflow: Research → Process → Share
        
        # 1. Create research documents
        research_docs = []
        for i in range(3):
            doc = await create_research_document(
                async_client,
                headers,
                f"Research Topic {i+1}"
            )
            research_docs.append(doc)
        
        # 2. Create analysis tool
        tool = await create_analysis_tool(async_client, headers)
        
        # 3. Process all documents
        analysis_results = []
        for doc in research_docs:
            result = await execute_tool(
                async_client,
                headers,
                tool["id"],
                {"document_id": doc["id"]}
            )
            analysis_results.append(result)
        
        # 4. Create summary document
        summary = await create_summary_document(
            async_client,
            headers,
            research_docs,
            analysis_results
        )
        
        # 5. Share with team
        team = await get_user_team(async_client, headers)
        share_resp = await share_with_team(
            async_client,
            headers,
            summary["id"],
            team["id"]
        )
        
        assert share_resp.status_code == 200
        
        # 6. Generate report
        report = await generate_report(
            async_client,
            headers,
            summary["id"],
            format="pdf"
        )
        
        assert report.status_code == 200
        assert report.headers["content-type"] == "application/pdf"
```

## Success Criteria

1. ✅ All API endpoints work together correctly
2. ✅ Data flows properly between systems
3. ✅ Transactions maintain consistency
4. ✅ WebSocket real-time features work
5. ✅ External integrations function properly
6. ✅ Complete user journeys succeed
7. ✅ Error handling works across systems
8. ✅ Performance is acceptable for workflows

## Integration Test Checklist

- [ ] Document lifecycle (CRUD + sharing)
- [ ] Knowledge extraction pipeline
- [ ] Tool creation and execution
- [ ] MCP server integration
- [ ] Team collaboration features
- [ ] Real-time WebSocket updates
- [ ] Cross-system workflows
- [ ] User onboarding flow
- [ ] Search across systems
- [ ] Notification delivery
- [ ] Export/Import features
- [ ] Billing integration
- [ ] Analytics collection

## Next Steps

After this task:
- Run integration tests: `pytest tests/integration -v -m integration`
- Generate coverage report for workflows
- Document any integration issues found
- Move on to Load tests (Task 010)

## Notes

- Use real database (test instance)
- Mock external services when needed
- Test both success and failure paths
- Verify data consistency after workflows
- Monitor for memory leaks during long tests