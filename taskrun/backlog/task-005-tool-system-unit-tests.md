# Task 005: Tool System Unit Tests

## Priority: HIGH
**Estimated Time**: 4-5 hours  
**Dependencies**: Tasks 001-002 (Pytest setup, fixtures)  
**Blocking**: None

## Why This Task is Critical

The Tool System enables MCP integration and custom tools but lacks:
1. **No schema validation tests** - Invalid tool definitions could break system
2. **No execution tests** - Tools might fail or timeout
3. **No sandbox tests** - Security vulnerabilities possible
4. **No MCP connection tests** - Integration might not work
5. **No versioning tests** - Tool updates could break existing flows

## What Needs to Be Done

### 1. Tool Model Tests

Create `tests/unit/models/test_tool.py`:
```python
"""Unit tests for Tool models."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4
import json
from src.infrastructure.database.models.tool import (
    Tool, ToolDefinition, MCPServer, ToolExecution
)

class TestToolModel:
    """Test Tool model validation."""
    
    def test_tool_creation_valid(self):
        """Test creating tool with valid data."""
        tool = Tool(
            name="web-scraper",
            display_name="Web Scraper",
            description="Scrapes web pages",
            category="data-collection",
            tenant_id=uuid4(),
            creator_id=uuid4()
        )
        assert tool.name == "web-scraper"
        assert tool.is_public is False  # Default
        assert tool.total_uses == 0
    
    @pytest.mark.parametrize("invalid_name", [
        "Web Scraper",  # No spaces
        "web_scraper",  # Must use hyphens
        "123-start",    # Can't start with number
        "a" * 65,       # Too long
        "web-",         # Can't end with hyphen
        "-web",         # Can't start with hyphen
    ])
    def test_tool_name_validation(self, invalid_name):
        """Test tool name format validation."""
        with pytest.raises(ValueError):
            Tool(
                name=invalid_name,
                tenant_id=uuid4(),
                creator_id=uuid4()
            )
    
    @pytest.mark.parametrize("category", [
        "data-collection",
        "text-processing", 
        "integration",
        "automation",
        "analysis"
    ])
    def test_valid_tool_categories(self, category):
        """Test valid tool categories."""
        tool = Tool(
            name="test-tool",
            category=category,
            tenant_id=uuid4(),
            creator_id=uuid4()
        )
        assert tool.category == category
    
    def test_tool_tags_validation(self):
        """Test tool tags constraints."""
        tool = Tool(
            name="test-tool",
            tenant_id=uuid4(),
            creator_id=uuid4()
        )
        
        # Valid tags
        tool.tags = ["web", "api", "json"]
        assert len(tool.tags) == 3
        
        # Too many tags
        with pytest.raises(ValueError):
            tool.tags = [f"tag{i}" for i in range(21)]  # Max 20
    
    def test_tool_statistics_tracking(self):
        """Test tool usage statistics."""
        tool = Tool(
            name="test-tool",
            tenant_id=uuid4(),
            creator_id=uuid4()
        )
        
        # Update statistics
        tool.record_execution(success=True, duration_ms=150)
        assert tool.total_uses == 1
        assert tool.success_count == 1
        assert tool.average_duration_ms == 150
        
        tool.record_execution(success=False, duration_ms=50)
        assert tool.total_uses == 2
        assert tool.success_count == 1
        assert tool.failure_count == 1
        assert tool.average_duration_ms == 100  # (150+50)/2
```

### 2. Tool Definition Tests

Create `tests/unit/models/test_tool_definition.py`:
```python
"""Unit tests for ToolDefinition model."""
import pytest
from uuid import uuid4
import json
from jsonschema import validate, ValidationError
from src.infrastructure.database.models.tool import ToolDefinition

class TestToolDefinition:
    """Test tool definition with JSON schemas."""
    
    def test_definition_creation(self):
        """Test creating tool definition."""
        schema = {
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "selector": {"type": "string"}
            },
            "required": ["url"]
        }
        
        definition = ToolDefinition(
            tool_id=uuid4(),
            definition_version="1.0.0",
            input_schema=schema,
            output_schema={"type": "object"}
        )
        
        assert definition.definition_version == "1.0.0"
        assert definition.is_current is True
        assert "url" in definition.input_schema["required"]
    
    def test_schema_validation(self):
        """Test JSON schema validation."""
        definition = ToolDefinition(
            tool_id=uuid4(),
            definition_version="1.0.0",
            input_schema={
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "minimum": 1, "maximum": 100}
                },
                "required": ["count"]
            }
        )
        
        # Valid input
        valid_input = {"count": 50}
        validate(valid_input, definition.input_schema)  # Should not raise
        
        # Invalid inputs
        invalid_inputs = [
            {"count": 0},      # Below minimum
            {"count": 101},    # Above maximum
            {"count": "50"},   # Wrong type
            {},                # Missing required
        ]
        
        for invalid_input in invalid_inputs:
            with pytest.raises(ValidationError):
                validate(invalid_input, definition.input_schema)
    
    def test_version_comparison(self):
        """Test version string comparison."""
        def1 = ToolDefinition(
            tool_id=uuid4(),
            definition_version="1.0.0"
        )
        
        def2 = ToolDefinition(
            tool_id=uuid4(),
            definition_version="1.1.0"
        )
        
        def3 = ToolDefinition(
            tool_id=uuid4(),
            definition_version="2.0.0"
        )
        
        assert def1.compare_version(def2) < 0  # 1.0.0 < 1.1.0
        assert def2.compare_version(def3) < 0  # 1.1.0 < 2.0.0
        assert def3.compare_version(def1) > 0  # 2.0.0 > 1.0.0
    
    def test_example_validation(self):
        """Test that examples match schema."""
        definition = ToolDefinition(
            tool_id=uuid4(),
            input_schema={
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "max_length": {"type": "integer"}
                }
            },
            examples=[
                {
                    "input": {"text": "Hello", "max_length": 10},
                    "output": {"result": "HELLO"}
                }
            ]
        )
        
        # Validate example against schema
        for example in definition.examples:
            validate(example["input"], definition.input_schema)
```

### 3. MCP Server Tests

Create `tests/unit/models/test_mcp_server.py`:
```python
"""Unit tests for MCPServer model."""
import pytest
from datetime import datetime, timedelta
from uuid import uuid4
from src.infrastructure.database.models.tool import MCPServer

class TestMCPServer:
    """Test MCP server configuration."""
    
    def test_mcp_server_creation(self):
        """Test creating MCP server config."""
        server = MCPServer(
            name="github-mcp",
            tenant_id=uuid4(),
            connection_type="stdio",
            connection_config={
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"]
            }
        )
        
        assert server.name == "github-mcp"
        assert server.connection_type == "stdio"
        assert server.is_healthy is None  # Not checked yet
    
    @pytest.mark.parametrize("conn_type,config,valid", [
        ("stdio", {"command": "npx", "args": []}, True),
        ("http", {"url": "http://localhost:8080"}, True),
        ("websocket", {"url": "ws://localhost:8080"}, True),
        ("invalid", {}, False),
        ("http", {"invalid": "config"}, False),  # Missing url
    ])
    def test_connection_config_validation(self, conn_type, config, valid):
        """Test connection configuration validation."""
        if valid:
            server = MCPServer(
                name="test",
                tenant_id=uuid4(),
                connection_type=conn_type,
                connection_config=config
            )
            assert server.connection_type == conn_type
        else:
            with pytest.raises(ValueError):
                MCPServer(
                    name="test",
                    tenant_id=uuid4(),
                    connection_type=conn_type,
                    connection_config=config
                )
    
    def test_health_check_tracking(self):
        """Test health check status tracking."""
        server = MCPServer(
            name="test",
            tenant_id=uuid4(),
            connection_type="http",
            connection_config={"url": "http://localhost:8080"}
        )
        
        # Record successful health check
        server.record_health_check(healthy=True, response_time_ms=50)
        assert server.is_healthy is True
        assert server.last_health_check is not None
        assert server.health_check_failures == 0
        
        # Record failed health checks
        for _ in range(3):
            server.record_health_check(healthy=False)
        
        assert server.is_healthy is False
        assert server.health_check_failures == 3
    
    def test_auto_reconnect_logic(self):
        """Test auto-reconnect configuration."""
        server = MCPServer(
            name="test",
            tenant_id=uuid4(),
            connection_type="websocket",
            connection_config={"url": "ws://localhost:8080"},
            auto_reconnect=True,
            max_reconnect_attempts=5
        )
        
        # Simulate connection failures
        assert server.should_reconnect() is True
        
        # Max out reconnect attempts
        server.reconnect_attempts = 5
        assert server.should_reconnect() is False
```

### 4. Tool Execution Tests

Create `tests/unit/repositories/test_tool_execution_repository.py`:
```python
"""Unit tests for ToolExecution repository."""
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timedelta
from uuid import uuid4
from src.infrastructure.database.repositories.tool import ToolExecutionRepository
from src.infrastructure.database.models.tool import ToolExecution

class TestToolExecutionRepository:
    """Test tool execution tracking."""
    
    @pytest.mark.asyncio
    async def test_create_execution_record(self, mock_session):
        """Test recording tool execution."""
        repo = ToolExecutionRepository(ToolExecution, mock_session)
        
        execution = await repo.create_execution(
            tool_id=uuid4(),
            user_id=uuid4(),
            input_data={"url": "https://example.com"},
            execution_context={
                "request_id": "req_123",
                "source": "api"
            }
        )
        
        assert execution is not None
        assert execution.status == "pending"
        assert mock_session.add.called
    
    @pytest.mark.asyncio
    async def test_update_execution_success(self, mock_session):
        """Test updating execution with success."""
        repo = ToolExecutionRepository(ToolExecution, mock_session)
        
        execution_id = uuid4()
        mock_execution = MagicMock(id=execution_id, started_at=datetime.utcnow())
        
        await repo.update_execution(
            execution_id=execution_id,
            status="completed",
            output_data={"result": "data"},
            duration_ms=150
        )
        
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_update_execution_failure(self, mock_session):
        """Test updating execution with failure."""
        repo = ToolExecutionRepository(ToolExecution, mock_session)
        
        error_details = {
            "error_type": "ValidationError",
            "message": "Invalid input",
            "traceback": "..."
        }
        
        await repo.update_execution(
            execution_id=uuid4(),
            status="failed",
            error_message="Validation failed",
            error_details=error_details,
            duration_ms=50
        )
        
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_execution_timeout_handling(self, mock_session):
        """Test handling execution timeouts."""
        repo = ToolExecutionRepository(ToolExecution, mock_session)
        
        # Find timed out executions
        mock_executions = [
            MagicMock(
                id=uuid4(),
                started_at=datetime.utcnow() - timedelta(minutes=10),
                status="running"
            )
        ]
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_executions
        mock_session.execute.return_value = mock_result
        
        timed_out = await repo.find_timed_out_executions(
            timeout_seconds=300  # 5 minutes
        )
        
        assert len(timed_out) == 1
        
        # Mark as timed out
        await repo.mark_timed_out(timed_out[0].id)
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_execution_statistics(self, mock_session):
        """Test computing execution statistics."""
        repo = ToolExecutionRepository(ToolExecution, mock_session)
        
        stats = await repo.get_execution_stats(
            tool_id=uuid4(),
            time_range="last_24h"
        )
        
        expected_stats = {
            "total_executions": 100,
            "successful": 85,
            "failed": 10,
            "timed_out": 5,
            "average_duration_ms": 250,
            "p95_duration_ms": 800,
            "p99_duration_ms": 1200
        }
        
        # Mock would return these stats
        for key, value in expected_stats.items():
            assert stats[key] == value
```

### 5. Tool Security Tests

Create `tests/unit/test_tool_security.py`:
```python
"""Unit tests for tool security features."""
import pytest
from uuid import uuid4
import json

class TestToolSecurity:
    """Test tool security and sandboxing."""
    
    def test_input_sanitization(self):
        """Test dangerous input sanitization."""
        dangerous_inputs = [
            {"cmd": "rm -rf /"},  # Command injection
            {"sql": "'; DROP TABLE users; --"},  # SQL injection
            {"path": "../../../etc/passwd"},  # Path traversal
            {"script": "<script>alert('xss')</script>"},  # XSS
        ]
        
        for dangerous_input in dangerous_inputs:
            sanitized = sanitize_tool_input(dangerous_input)
            assert sanitized != dangerous_input
            assert "DROP TABLE" not in str(sanitized)
            assert "../" not in str(sanitized)
    
    def test_sandbox_restrictions(self):
        """Test sandbox execution restrictions."""
        sandbox_config = {
            "network_access": False,
            "filesystem_access": "read_only",
            "max_memory_mb": 512,
            "max_cpu_seconds": 30,
            "allowed_imports": ["json", "math", "datetime"]
        }
        
        # Test network restriction
        with pytest.raises(SecurityError):
            execute_in_sandbox(
                code="import requests; requests.get('http://example.com')",
                config=sandbox_config
            )
        
        # Test filesystem restriction
        with pytest.raises(SecurityError):
            execute_in_sandbox(
                code="open('/etc/passwd', 'w')",
                config=sandbox_config
            )
    
    def test_resource_limits(self):
        """Test resource limit enforcement."""
        # Test memory limit
        with pytest.raises(MemoryError):
            execute_with_limits(
                func=lambda: [0] * (1024 * 1024 * 1024),  # 1GB array
                max_memory_mb=512
            )
        
        # Test time limit
        with pytest.raises(TimeoutError):
            execute_with_limits(
                func=lambda: time.sleep(60),
                max_seconds=30
            )
    
    def test_output_size_limits(self):
        """Test output size restrictions."""
        large_output = {"data": "x" * (10 * 1024 * 1024)}  # 10MB
        
        with pytest.raises(ValueError):
            validate_tool_output(
                output=large_output,
                max_size_mb=5
            )
```

### 6. Tool Integration Tests

Create `tests/unit/test_tool_integration.py`:
```python
"""Unit tests for tool integration scenarios."""
import pytest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

class TestToolIntegration:
    """Test tool integration with MCP servers."""
    
    @pytest.mark.asyncio
    async def test_tool_discovery_from_mcp(self):
        """Test discovering tools from MCP server."""
        mock_mcp_response = {
            "tools": [
                {
                    "name": "fetch-url",
                    "description": "Fetches URL content",
                    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}
                },
                {
                    "name": "parse-json",
                    "description": "Parses JSON string",
                    "inputSchema": {"type": "object", "properties": {"json": {"type": "string"}}}
                }
            ]
        }
        
        with patch("mcp_client.list_tools", return_value=mock_mcp_response):
            tools = await discover_mcp_tools(server_id=uuid4())
        
        assert len(tools) == 2
        assert tools[0]["name"] == "fetch-url"
    
    @pytest.mark.asyncio
    async def test_tool_execution_via_mcp(self):
        """Test executing tool through MCP server."""
        mock_execution_result = {
            "success": True,
            "output": {"content": "Hello World", "status": 200}
        }
        
        with patch("mcp_client.execute_tool", return_value=mock_execution_result):
            result = await execute_mcp_tool(
                server_id=uuid4(),
                tool_name="fetch-url",
                input_data={"url": "https://example.com"}
            )
        
        assert result["success"] is True
        assert "content" in result["output"]
    
    @pytest.mark.asyncio
    async def test_tool_chaining(self):
        """Test chaining multiple tools."""
        # First tool fetches data
        fetch_result = {"content": '{"message": "Hello"}'}
        
        # Second tool parses JSON
        parse_result = {"message": "Hello"}
        
        with patch("execute_tool") as mock_execute:
            mock_execute.side_effect = [fetch_result, parse_result]
            
            chain_result = await execute_tool_chain([
                {"tool": "fetch-url", "input": {"url": "https://api.example.com"}},
                {"tool": "parse-json", "input": {"json": "$previous.content"}}
            ])
        
        assert chain_result["final_output"] == {"message": "Hello"}
        assert len(chain_result["steps"]) == 2
```

## Success Criteria

1. ✅ Tool name validation enforces naming conventions
2. ✅ JSON schema validation is thoroughly tested
3. ✅ MCP connection types are validated
4. ✅ Execution tracking includes success/failure/timeout
5. ✅ Security features like sandboxing are tested
6. ✅ Resource limits are enforced
7. ✅ Tool versioning logic is tested
8. ✅ Integration scenarios are covered

## Common Patterns to Test

1. **Schema Validation**: Invalid schemas, missing required fields
2. **Version Management**: Upgrade, downgrade, compatibility
3. **Execution States**: Pending, running, completed, failed, timeout
4. **Security**: Input sanitization, sandboxing, resource limits
5. **MCP Integration**: Discovery, execution, error handling
6. **Statistics**: Usage tracking, performance metrics
7. **Error Handling**: Network failures, invalid responses

## Next Steps

After this task:
- Run tests: `pytest tests/unit/models/test_tool.py -v`
- Check coverage: `pytest tests/unit --cov=src.infrastructure.database.models.tool`
- Move on to Security tests (Task 006)
- Later integrate with performance tests (Task 008)

## Notes

- Mock all external MCP connections
- Test both sync and async tool execution
- Verify sandbox isolation works
- Test resource limit enforcement
- Check error messages are helpful