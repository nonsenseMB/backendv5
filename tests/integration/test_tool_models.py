"""
Integration tests for Tool System models.
Tests tool definitions, MCP server integration, and execution tracking.
"""
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from src.infrastructure.database.session import get_async_session, init_db
from src.infrastructure.database.unit_of_work import UnitOfWork


async def test_tool_system_integration():
    """Test complete Tool System integration."""
    print("🛠️ Testing Tool System Integration...")
    
    await init_db()
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup: Create tenant and user
            print("\n1. Setting up test data...")
            tenant = await uow.tenants.create(
                name="Tool Test Corp",
                slug="tool-test",
                plan_type="enterprise",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="tool_test_123",
                email="tools@example.com",
                username="tool_user",
                full_name="Tool Test User",
                is_active=True
            )
            
            team = await uow.with_tenant(tenant.id).teams.create(
                name="Development Team",
                slug="development-team",
                description="Team for tool development",
                created_by=user.id
            )
            
            print(f"   Created tenant: {tenant.name}")
            print(f"   Created user: {user.email}")
            print(f"   Created team: {team.name}")
            
            # Test Tool CRUD
            print("\n2. Testing Tool CRUD...")
            tenant_uow = uow.with_tenant(tenant.id)
            
            # Create different types of tools
            tools = []
            tool_data = [
                {
                    "name": "file_reader",
                    "display_name": "File Reader",
                    "description": "Reads files from the filesystem",
                    "category": "file",
                    "tool_type": "builtin",
                    "version": "1.0.0",
                    "is_system_tool": True,
                    "created_by": user.id,
                    "tags": ["file", "io", "builtin"]
                },
                {
                    "name": "web_scraper",
                    "display_name": "Web Scraper",
                    "description": "Scrapes content from web pages",
                    "category": "web",
                    "tool_type": "api",
                    "version": "2.1.0",
                    "is_system_tool": False,
                    "created_by": user.id,
                    "team_id": team.id,
                    "tags": ["web", "scraping", "http"]
                },
                {
                    "name": "custom_calculator",
                    "display_name": "Custom Calculator",
                    "description": "Performs complex mathematical calculations",
                    "category": "custom",
                    "tool_type": "custom",
                    "version": "1.5.2",
                    "is_system_tool": False,
                    "requires_approval": True,
                    "created_by": user.id,
                    "tags": ["math", "calculation", "custom"]
                }
            ]
            
            for data in tool_data:
                tool = await tenant_uow.tools.create(**data)
                tools.append(tool)
                print(f"   Created tool: {tool.display_name} ({tool.tool_type})")
            
            # Test tool retrieval methods
            print("\n3. Testing tool retrieval...")
            
            # Get by name
            file_reader = await tenant_uow.tools.get_by_name("file_reader", tenant.id)
            assert file_reader.display_name == "File Reader"
            print(f"   Retrieved tool by name: {file_reader.name}")
            
            # Get available tools
            available_tools = await tenant_uow.tools.get_available_tools(
                tenant_id=tenant.id,
                include_system=True
            )
            assert len(available_tools) >= 3
            print(f"   Found {len(available_tools)} available tools")
            
            # Get system tools
            system_tools = await uow.tools.get_system_tools()
            system_tool_names = [t.name for t in system_tools]
            assert "file_reader" in system_tool_names
            print(f"   Found {len(system_tools)} system tools")
            
            # Search tools
            search_results = await tenant_uow.tools.search_tools(
                query="web",
                tenant_id=tenant.id
            )
            assert len(search_results) >= 1
            print(f"   Search for 'web' found {len(search_results)} tools")
            
            # Get user tools
            user_tools = await tenant_uow.tools.get_user_tools(user.id, tenant.id)
            assert len(user_tools) == 3
            print(f"   User created {len(user_tools)} tools")
            
            print("\n✅ Tool system integration tests passed!")
            
        break


async def test_tool_definition_versioning():
    """Test tool definition versioning and management."""
    print("\n📋 Testing Tool Definition Versioning...")
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup
            tenant = await uow.tenants.create(
                name="Definition Test Corp",
                slug="definition-test",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="def_test_123",
                email="definitions@example.com",
                username="def_user",
                full_name="Definition Test User"
            )
            
            # Create a tool
            tenant_uow = uow.with_tenant(tenant.id)
            tool = await tenant_uow.tools.create(
                name="versioned_tool",
                display_name="Versioned Tool",
                description="Tool for testing versioning",
                category="custom",
                tool_type="custom",
                created_by=user.id
            )
            
            print(f"   Created tool: {tool.display_name}")
            
            # Test ToolDefinition versioning
            print("\n   Testing definition versioning...")
            
            # Create initial definition
            schema_v1 = {
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "input_text": {
                            "type": "string",
                            "description": "Text to process"
                        }
                    },
                    "required": ["input_text"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "result": {"type": "string"}
                    }
                }
            }
            
            config_v1 = {
                "timeout_seconds": 30,
                "max_retries": 3,
                "requires_confirmation": False
            }
            
            def_v1 = await uow.tool_definitions.create_new_version(
                tool_id=tool.id,
                schema_data=schema_v1,
                execution_config=config_v1,
                version="1.0.0"
            )
            
            print(f"     Created definition v{def_v1.definition_version}")
            assert def_v1.is_current == True
            assert def_v1.definition_version == "1.0.0"
            
            # Create updated definition
            schema_v2 = {
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "input_text": {
                            "type": "string",
                            "description": "Text to process"
                        },
                        "options": {
                            "type": "object",
                            "properties": {
                                "case_sensitive": {"type": "boolean", "default": False}
                            }
                        }
                    },
                    "required": ["input_text"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "result": {"type": "string"},
                        "metadata": {"type": "object"}
                    }
                }
            }
            
            config_v2 = {
                "timeout_seconds": 45,
                "max_retries": 5,
                "requires_confirmation": True
            }
            
            def_v2 = await uow.tool_definitions.create_new_version(
                tool_id=tool.id,
                schema_data=schema_v2,
                execution_config=config_v2
            )
            
            print(f"     Created definition v{def_v2.definition_version}")
            assert def_v2.is_current == True
            assert def_v2.definition_version == "1.0.1"
            
            # Verify v1 is no longer current
            await session.refresh(def_v1)
            assert def_v1.is_current == False
            
            # Test definition retrieval
            current_def = await uow.tool_definitions.get_current_definition(tool.id)
            assert current_def.id == def_v2.id
            print(f"     Current definition is v{current_def.definition_version}")
            
            # Test definition history
            history = await uow.tool_definitions.get_definition_history(tool.id)
            assert len(history) == 2
            print(f"     Definition history contains {len(history)} versions")
            
            # Test definition validation
            validation_success = await uow.tool_definitions.validate_definition(def_v2.id)
            assert validation_success == True
            print(f"     Definition validation: {'✅' if validation_success else '❌'}")
            
            print("✅ Tool definition versioning tests passed!")
            
        break


async def test_mcp_server_integration():
    """Test MCP server management and integration."""
    print("\n🔌 Testing MCP Server Integration...")
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup
            tenant = await uow.tenants.create(
                name="MCP Test Corp",
                slug="mcp-test",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="mcp_test_123",
                email="mcp@example.com",
                username="mcp_user",
                full_name="MCP Test User"
            )
            
            print(f"   Created tenant: {tenant.name}")
            print(f"   Created user: {user.email}")
            
            # Test MCPServer CRUD
            print("\n   Testing MCP Server management...")
            tenant_uow = uow.with_tenant(tenant.id)
            
            # Create different types of MCP servers
            servers = []
            server_data = [
                {
                    "name": "github_mcp",
                    "display_name": "GitHub MCP Server",
                    "description": "Provides GitHub repository access",
                    "server_type": "stdio",
                    "connection_config": {
                        "command": "github-mcp-server",
                        "args": ["--token", "${GITHUB_TOKEN}"]
                    },
                    "auth_type": "bearer",
                    "auth_config": {"token_env": "GITHUB_TOKEN"},
                    "available_tools": ["list_repos", "get_file", "create_issue"],
                    "created_by": user.id
                },
                {
                    "name": "filesystem_mcp",
                    "display_name": "Filesystem MCP Server",
                    "description": "Provides filesystem access",
                    "server_type": "http",
                    "base_url": "http://localhost:8001",
                    "connection_config": {
                        "endpoint": "/mcp",
                        "timeout": 30
                    },
                    "auth_type": "api_key",
                    "auth_config": {"header": "X-API-Key", "key_env": "FS_API_KEY"},
                    "available_tools": ["read_file", "write_file", "list_directory"],
                    "created_by": user.id
                },
                {
                    "name": "database_mcp",
                    "display_name": "Database MCP Server",
                    "description": "Provides database query access",
                    "server_type": "websocket",
                    "base_url": "ws://localhost:8002/ws",
                    "connection_config": {
                        "protocol": "mcp-websocket",
                        "heartbeat_interval": 30
                    },
                    "auth_type": "none",
                    "available_tools": ["execute_query", "get_schema", "list_tables"],
                    "created_by": user.id
                }
            ]
            
            for data in server_data:
                server = await tenant_uow.mcp_servers.create(**data)
                servers.append(server)
                print(f"     Created MCP server: {server.display_name} ({server.server_type})")
            
            # Test server retrieval
            print("\n   Testing MCP server retrieval...")
            
            # Get by name
            github_server = await tenant_uow.mcp_servers.get_by_name("github_mcp", tenant.id)
            assert github_server.display_name == "GitHub MCP Server"
            print(f"     Retrieved server by name: {github_server.name}")
            
            # Get active servers
            active_servers = await tenant_uow.mcp_servers.get_active_servers(tenant.id)
            assert len(active_servers) == 3  # All should be active by default
            print(f"     Found {len(active_servers)} active servers")
            
            # Get servers by type
            stdio_servers = await tenant_uow.mcp_servers.get_servers_by_type("stdio", tenant.id)
            assert len(stdio_servers) == 1
            print(f"     Found {len(stdio_servers)} stdio servers")
            
            # Test server health and statistics
            print("\n   Testing server health and statistics...")
            
            # Update health status
            success = await tenant_uow.mcp_servers.update_health_status(
                servers[0].id,
                "healthy",
                retry_count=0
            )
            assert success == True
            print(f"     Updated server health status to 'healthy'")
            
            # Update tools info
            new_tools = ["list_repos", "get_file", "create_issue", "create_pr"]
            tool_schemas = {
                "list_repos": {"input": {"type": "object"}, "output": {"type": "array"}},
                "get_file": {"input": {"type": "object", "properties": {"path": {"type": "string"}}}}
            }
            
            success = await tenant_uow.mcp_servers.update_tools_info(
                servers[0].id,
                new_tools,
                tool_schemas
            )
            assert success == True
            
            # Refresh and verify
            await session.refresh(servers[0])
            assert len(servers[0].available_tools) == 4
            print(f"     Updated server tools: {len(servers[0].available_tools)} tools available")
            
            # Update usage statistics
            success = await tenant_uow.mcp_servers.update_usage_stats(
                servers[0].id,
                successful=True,
                response_time_ms=150
            )
            assert success == True
            
            await session.refresh(servers[0])
            assert servers[0].total_requests == 1
            assert servers[0].successful_requests == 1
            print(f"     Updated usage stats: {servers[0].total_requests} total, {servers[0].successful_requests} successful")
            
            print("✅ MCP Server integration tests passed!")
            
        break


async def test_tool_execution_tracking():
    """Test tool execution tracking and statistics."""
    print("\n📊 Testing Tool Execution Tracking...")
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup
            tenant = await uow.tenants.create(
                name="Execution Test Corp",
                slug="execution-test",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="exec_test_123",
                email="execution@example.com",
                username="exec_user",
                full_name="Execution Test User"
            )
            
            # Create conversation for context
            tenant_uow = uow.with_tenant(tenant.id)
            conversation = await tenant_uow.conversations.create(
                user_id=user.id,
                title="Tool Execution Test"
            )
            
            # Create a tool
            tool = await tenant_uow.tools.create(
                name="test_executor",
                display_name="Test Executor",
                description="Tool for testing execution tracking",
                category="test",
                tool_type="custom",
                created_by=user.id
            )
            
            print(f"   Created tool: {tool.display_name}")
            print(f"   Created conversation: {conversation.title}")
            
            # Test ToolExecution CRUD
            print("\n   Testing tool execution tracking...")
            
            # Create tool executions
            executions = []
            execution_data = [
                {
                    "tool_id": tool.id,
                    "user_id": user.id,
                    "conversation_id": conversation.id,
                    "execution_id": f"exec_{uuid4().hex[:16]}",
                    "tool_version": "1.0.0",
                    "input_data": {"text": "Hello, world!", "options": {"uppercase": True}},
                    "started_at": datetime.utcnow(),
                    "status": "running",
                    "execution_context": {"session_id": "test_session_1"},
                    "was_sandboxed": True
                },
                {
                    "tool_id": tool.id,
                    "user_id": user.id,
                    "conversation_id": conversation.id,
                    "execution_id": f"exec_{uuid4().hex[:16]}",
                    "tool_version": "1.0.0",
                    "input_data": {"text": "Test calculation", "operation": "multiply", "values": [2, 3, 4]},
                    "started_at": datetime.utcnow() - timedelta(minutes=5),
                    "status": "pending",
                    "execution_context": {"session_id": "test_session_2"},
                    "was_sandboxed": True
                }
            ]
            
            for data in execution_data:
                execution = await uow.tool_executions.create(**data)
                executions.append(execution)
                print(f"     Created execution: {execution.execution_id} (status: {execution.status})")
            
            # Test execution updates
            print("\n   Testing execution status updates...")
            
            # Complete first execution successfully
            success = await uow.tool_executions.update_execution_status(
                executions[0].execution_id,
                status="completed",
                output_data={"result": "HELLO, WORLD!", "transformed": True},
                exit_code=0
            )
            assert success == True
            print(f"     Completed execution: {executions[0].execution_id}")
            
            # Fail second execution
            success = await uow.tool_executions.update_execution_status(
                executions[1].execution_id,
                status="failed",
                error_data={"error": "Invalid operation", "code": "INVALID_OP"},
                exit_code=1
            )
            assert success == True
            print(f"     Failed execution: {executions[1].execution_id}")
            
            # Test execution retrieval
            print("\n   Testing execution retrieval...")
            
            # Get by execution ID
            exec_by_id = await uow.tool_executions.get_by_execution_id(executions[0].execution_id)
            assert exec_by_id.status == "completed"
            print(f"     Retrieved execution by ID: {exec_by_id.execution_id}")
            
            # Get user executions
            user_executions = await uow.tool_executions.get_user_executions(
                user_id=user.id,
                limit=10
            )
            assert len(user_executions) == 2
            print(f"     User has {len(user_executions)} executions")
            
            # Get tool executions
            tool_executions = await uow.tool_executions.get_tool_executions(
                tool_id=tool.id,
                status="completed"
            )
            assert len(tool_executions) == 1
            print(f"     Tool has {len(tool_executions)} completed executions")
            
            # Get conversation executions
            conv_executions = await uow.tool_executions.get_conversation_executions(
                conversation_id=conversation.id
            )
            assert len(conv_executions) == 2
            print(f"     Conversation has {len(conv_executions)} executions")
            
            # Test execution statistics
            print("\n   Testing execution statistics...")
            
            stats = await uow.tool_executions.get_execution_stats(
                tool_id=tool.id,
                days=30
            )
            
            assert stats["total_executions"] == 2
            assert stats["successful_executions"] == 1
            assert stats["failed_executions"] == 1
            assert stats["success_rate"] == 50.0
            print(f"     Tool stats: {stats['total_executions']} total, {stats['success_rate']}% success rate")
            
            # Test tool usage statistics update
            print("\n   Testing tool usage statistics...")
            
            success = await tenant_uow.tools.update_usage_stats(
                tool.id,
                execution_successful=True,
                execution_time_ms=250
            )
            assert success == True
            
            success = await tenant_uow.tools.update_usage_stats(
                tool.id,
                execution_successful=False,
                execution_time_ms=100
            )
            assert success == True
            
            # Refresh and verify
            await session.refresh(tool)
            assert tool.total_executions == 2
            assert tool.successful_executions == 1
            assert tool.average_execution_time == 175.0  # (250 + 100) / 2
            print(f"     Tool stats updated: {tool.total_executions} executions, avg time: {tool.average_execution_time}ms")
            
            print("✅ Tool execution tracking tests passed!")
            
        break


async def test_tool_mcp_integration():
    """Test tool definition with MCP server integration."""
    print("\n🔗 Testing Tool-MCP Integration...")
    
    async for session in get_async_session():
        async with UnitOfWork(session) as uow:
            # Setup
            tenant = await uow.tenants.create(
                name="Tool-MCP Test Corp",
                slug="tool-mcp-test",
                is_active=True
            )
            
            user = await uow.users.create(
                external_id="tool_mcp_test_123",
                email="toolmcp@example.com",
                username="tool_mcp_user",
                full_name="Tool-MCP Test User"
            )
            
            # Create MCP server
            tenant_uow = uow.with_tenant(tenant.id)
            mcp_server = await tenant_uow.mcp_servers.create(
                name="github_integration",
                display_name="GitHub Integration Server",
                description="MCP server for GitHub operations",
                server_type="stdio",
                connection_config={"command": "github-mcp", "args": ["--config", "github.json"]},
                available_tools=["create_repo", "list_issues", "create_pr"],
                created_by=user.id
            )
            
            # Create tool that uses MCP server
            tool = await tenant_uow.tools.create(
                name="github_repo_creator",
                display_name="GitHub Repository Creator",
                description="Creates GitHub repositories via MCP",
                category="integration",
                tool_type="mcp",
                created_by=user.id
            )
            
            print(f"   Created MCP server: {mcp_server.display_name}")
            print(f"   Created MCP tool: {tool.display_name}")
            
            # Create tool definition that references MCP server
            print("\n   Testing MCP tool definition...")
            
            mcp_schema = {
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "repo_name": {"type": "string", "description": "Repository name"},
                        "description": {"type": "string", "description": "Repository description"},
                        "private": {"type": "boolean", "default": False}
                    },
                    "required": ["repo_name"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "repo_url": {"type": "string"},
                        "clone_url": {"type": "string"},
                        "success": {"type": "boolean"}
                    }
                }
            }
            
            mcp_config = {
                "timeout_seconds": 60,
                "max_retries": 3,
                "requires_confirmation": True
            }
            
            definition = await uow.tool_definitions.create(
                tool_id=tool.id,
                input_schema=mcp_schema["input_schema"],
                output_schema=mcp_schema["output_schema"],
                execution_config=mcp_config,
                mcp_server_id=mcp_server.id,
                mcp_tool_name="create_repo",
                is_current=True,
                is_valid=True
            )
            
            print(f"     Created MCP tool definition: {definition.mcp_tool_name}")
            assert definition.mcp_server_id == mcp_server.id
            assert definition.mcp_tool_name == "create_repo"
            
            # Test tool definition with MCP server relationship
            current_def = await uow.tool_definitions.get_current_definition(tool.id)
            assert current_def.mcp_server_id == mcp_server.id
            print(f"     Tool definition linked to MCP server: {mcp_server.name}")
            
            # Create execution that would use MCP server
            execution = await uow.tool_executions.create(
                tool_id=tool.id,
                user_id=user.id,
                execution_id=f"mcp_exec_{uuid4().hex[:12]}",
                input_data={
                    "repo_name": "test-integration-repo",
                    "description": "Repository created via MCP integration test",
                    "private": False
                },
                started_at=datetime.utcnow(),
                status="pending",
                execution_context={"mcp_server": mcp_server.name},
                was_sandboxed=True
            )
            
            print(f"     Created MCP execution: {execution.execution_id}")
            
            # Simulate successful execution
            await uow.tool_executions.update_execution_status(
                execution.execution_id,
                status="completed",
                output_data={
                    "repo_url": "https://github.com/testuser/test-integration-repo",
                    "clone_url": "git@github.com:testuser/test-integration-repo.git",
                    "success": True
                },
                exit_code=0
            )
            
            print(f"     Completed MCP execution successfully")
            
            # Update MCP server usage stats
            await tenant_uow.mcp_servers.update_usage_stats(
                mcp_server.id,
                successful=True,
                response_time_ms=2500
            )
            
            await session.refresh(mcp_server)
            print(f"     Updated MCP server stats: {mcp_server.total_requests} requests, {mcp_server.average_response_time}ms avg")
            
            print("✅ Tool-MCP integration tests passed!")
            
        break


async def main():
    """Run all Tool System integration tests."""
    try:
        await test_tool_system_integration()
        await test_tool_definition_versioning()
        await test_mcp_server_integration()
        await test_tool_execution_tracking()
        await test_tool_mcp_integration()
        print("\n🎉 All Tool System integration tests completed successfully!")
        return True
    except Exception as e:
        print(f"\n❌ Tool System tests failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)