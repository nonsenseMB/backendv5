"""
Tool System models for JSON-based tool definitions and MCP integration.
Supports dynamic tool loading and execution tracking.
"""

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..base import BaseModel, TenantAwareModel


class Tool(TenantAwareModel):
    """
    Tool registry with JSON-based definitions.
    Supports both built-in and custom tools.
    """
    __tablename__ = 'tools'

    # Identity
    name = Column(String(255), nullable=False)  # Unique tool identifier
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=False)  # system, file, web, custom

    # Tool Type
    tool_type = Column(String(50), nullable=False)  # builtin, mcp, custom, api
    version = Column(String(50), nullable=False, default='1.0.0')

    # Availability
    is_system_tool = Column(Boolean, default=False)  # Available to all tenants
    is_public = Column(Boolean, default=False)  # Public in marketplace
    requires_approval = Column(Boolean, default=True)

    # Creator
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey('teams.id'), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_status = Column(String(50), default='pending')  # pending, approved, rejected

    # Usage Statistics
    total_executions = Column(Integer, default=0)
    successful_executions = Column(Integer, default=0)
    average_execution_time = Column(Float, default=0.0)
    last_used_at = Column(DateTime, nullable=True)

    # Additional data
    tags = Column(JSON, default=list)
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    creator = relationship("User")
    team = relationship("Team")
    definitions = relationship("ToolDefinition", back_populates="tool", cascade="all, delete-orphan")
    executions = relationship("ToolExecution", back_populates="tool")

    def __repr__(self):
        return f"<Tool(name='{self.name}', type='{self.tool_type}')>"


class ToolDefinition(BaseModel):
    """
    JSON schema definitions for tools.
    Stores the actual tool configuration and parameters.
    """
    __tablename__ = 'tool_definitions'

    # Foreign Key
    tool_id = Column(UUID(as_uuid=True), ForeignKey('tools.id', ondelete='CASCADE'), nullable=False)

    # Definition
    definition_version = Column(String(50), nullable=False, default='1.0.0')
    is_current = Column(Boolean, default=True)

    # JSON Schema
    schema_version = Column(String(20), nullable=False, default='draft-07')
    input_schema = Column(JSON, nullable=False)  # JSON Schema for inputs
    output_schema = Column(JSON, nullable=True)  # Expected output format

    # Execution Configuration
    execution_config = Column(JSON, default=dict)  # Runtime configuration
    timeout_seconds = Column(Integer, default=30)
    max_retries = Column(Integer, default=3)
    requires_confirmation = Column(Boolean, default=False)

    # MCP Server Reference (if applicable)
    mcp_server_id = Column(UUID(as_uuid=True), ForeignKey('mcp_servers.id'), nullable=True)
    mcp_tool_name = Column(String(255), nullable=True)

    # API Configuration (if tool_type is 'api')
    api_endpoint = Column(Text, nullable=True)
    api_method = Column(String(10), nullable=True)  # GET, POST, PUT, DELETE
    api_headers = Column(JSON, default=dict)
    api_auth_type = Column(String(50), nullable=True)  # bearer, basic, api_key

    # Code Execution (if tool_type is 'custom')
    execution_code = Column(Text, nullable=True)  # Python code
    execution_environment = Column(String(50), nullable=True)  # python, nodejs, shell

    # Security
    sandbox_enabled = Column(Boolean, default=True)
    allowed_domains = Column(JSON, default=list)  # For API tools
    security_level = Column(String(50), default='medium')  # low, medium, high

    # Validation
    is_valid = Column(Boolean, default=False)
    validation_errors = Column(JSON, default=list)
    last_validated_at = Column(DateTime, nullable=True)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    tool = relationship("Tool", back_populates="definitions")
    mcp_server = relationship("MCPServer")

    def __repr__(self):
        return f"<ToolDefinition(tool_id={self.tool_id}, version='{self.definition_version}')>"


class MCPServer(TenantAwareModel):
    """
    Model Context Protocol (MCP) server configuration.
    Manages connections to external MCP servers.
    """
    __tablename__ = 'mcp_servers'

    # Identity
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Connection
    server_type = Column(String(50), nullable=False)  # stdio, http, websocket
    connection_config = Column(JSON, nullable=False)  # Server-specific config
    base_url = Column(Text, nullable=True)  # For HTTP/WebSocket servers

    # Authentication
    auth_type = Column(String(50), nullable=True)  # none, bearer, api_key
    auth_config = Column(JSON, default=dict)  # Auth configuration

    # Available Tools
    available_tools = Column(JSON, default=list)  # List of tool names
    tool_schemas = Column(JSON, default=dict)  # Tool schemas from server
    last_sync_at = Column(DateTime, nullable=True)

    # Health
    is_active = Column(Boolean, default=True)
    health_status = Column(String(50), default='unknown')  # healthy, degraded, down
    last_health_check = Column(DateTime, nullable=True)
    connection_retries = Column(Integer, default=0)

    # Usage
    total_requests = Column(Integer, default=0)
    successful_requests = Column(Integer, default=0)
    average_response_time = Column(Float, default=0.0)

    # Configuration
    timeout_seconds = Column(Integer, default=30)
    max_retries = Column(Integer, default=3)
    enable_auto_sync = Column(Boolean, default=True)

    # Creator
    created_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    creator = relationship("User")
    tool_definitions = relationship("ToolDefinition", back_populates="mcp_server")

    def __repr__(self):
        return f"<MCPServer(name='{self.name}', type='{self.server_type}', status='{self.health_status}')>"


class ToolExecution(BaseModel):
    """
    Tool execution history and results.
    Tracks all tool invocations for auditing and debugging.
    """
    __tablename__ = 'tool_executions'

    # Foreign Keys
    tool_id = Column(UUID(as_uuid=True), ForeignKey('tools.id'), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False)
    conversation_id = Column(UUID(as_uuid=True), ForeignKey('conversations.id'), nullable=True)
    message_id = Column(UUID(as_uuid=True), ForeignKey('messages.id'), nullable=True)

    # Execution Info
    execution_id = Column(String(255), unique=True, nullable=False)  # Unique execution identifier
    tool_version = Column(String(50), nullable=True)

    # Input/Output
    input_data = Column(JSON, nullable=False)
    output_data = Column(JSON, nullable=True)
    error_data = Column(JSON, nullable=True)

    # Timing
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)

    # Status
    status = Column(String(50), nullable=False)  # pending, running, completed, failed, timeout
    exit_code = Column(Integer, nullable=True)
    retry_count = Column(Integer, default=0)

    # Context
    execution_context = Column(JSON, default=dict)  # Additional context
    user_agent = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)

    # Security
    was_sandboxed = Column(Boolean, default=True)
    security_violations = Column(JSON, default=list)

    # Additional data
    extra_data = Column('metadata', JSON, default=dict)

    # Relationships
    tool = relationship("Tool", back_populates="executions")
    user = relationship("User")
    conversation = relationship("Conversation")
    message = relationship("Message")

    def __repr__(self):
        return f"<ToolExecution(id='{self.execution_id}', tool={self.tool_id}, status='{self.status}')>"
