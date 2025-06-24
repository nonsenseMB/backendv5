"""
Tests for agent loader functionality.
"""
import pytest
from unittest.mock import MagicMock, patch

from src.agents.exceptions import ValidationError
from src.agents.loader import AgentLoader, GraphDefinitionParser, create_default_agent_definitions
from src.infrastructure.database.models.agent import Agent


class TestGraphDefinitionParser:
    """Test graph definition parsing and validation."""
    
    def test_parse_valid_definition(self):
        """Test parsing a valid graph definition."""
        parser = GraphDefinitionParser()
        
        definition = {
            "nodes": [
                {"id": "input", "type": "input", "name": "User Input"},
                {"id": "llm", "type": "llm", "name": "LLM"},
                {"id": "output", "type": "output", "name": "Output"}
            ],
            "edges": [
                {"from": "START", "to": "input"},
                {"from": "input", "to": "llm"},
                {"from": "llm", "to": "output"},
                {"from": "output", "to": "END"}
            ],
            "entry_point": "input"
        }
        
        result = parser.parse(definition)
        assert result == definition
    
    def test_parse_missing_required_fields(self):
        """Test parsing fails with missing required fields."""
        parser = GraphDefinitionParser()
        
        # Missing nodes
        with pytest.raises(ValidationError, match="missing required field: nodes"):
            parser.parse({"edges": [], "entry_point": "input"})
        
        # Missing edges
        with pytest.raises(ValidationError, match="missing required field: edges"):
            parser.parse({"nodes": [], "entry_point": "input"})
        
        # Missing entry_point
        with pytest.raises(ValidationError, match="missing required field: entry_point"):
            parser.parse({"nodes": [], "edges": []})
    
    def test_parse_empty_nodes(self):
        """Test parsing fails with empty nodes."""
        parser = GraphDefinitionParser()
        
        with pytest.raises(ValidationError, match="must have at least one node"):
            parser.parse({
                "nodes": [],
                "edges": [],
                "entry_point": "input"
            })
    
    def test_parse_invalid_node_type(self):
        """Test parsing fails with invalid node type."""
        parser = GraphDefinitionParser()
        
        definition = {
            "nodes": [
                {"id": "test", "type": "invalid_type", "name": "Test"}
            ],
            "edges": [],
            "entry_point": "test"
        }
        
        with pytest.raises(ValidationError, match="Unknown node type: invalid_type"):
            parser.parse(definition)
    
    def test_parse_invalid_edge_references(self):
        """Test parsing fails with invalid edge references."""
        parser = GraphDefinitionParser()
        
        definition = {
            "nodes": [
                {"id": "input", "type": "input", "name": "Input"}
            ],
            "edges": [
                {"from": "invalid", "to": "input"}
            ],
            "entry_point": "input"
        }
        
        with pytest.raises(ValidationError, match="references unknown node: invalid"):
            parser.parse(definition)
    
    def test_parse_invalid_entry_point(self):
        """Test parsing fails with invalid entry point."""
        parser = GraphDefinitionParser()
        
        definition = {
            "nodes": [
                {"id": "input", "type": "input", "name": "Input"}
            ],
            "edges": [],
            "entry_point": "invalid"
        }
        
        with pytest.raises(ValidationError, match="Entry point 'invalid' not found"):
            parser.parse(definition)


class TestAgentLoader:
    """Test agent loader functionality."""
    
    @pytest.fixture
    def mock_llm(self):
        """Mock LLM provider."""
        return MagicMock()
    
    @pytest.fixture
    def loader(self, mock_llm):
        """Create agent loader with mocked dependencies."""
        return AgentLoader(llm_provider=mock_llm)
    
    @pytest.fixture
    def simple_agent(self):
        """Create a simple test agent."""
        return Agent(
            id="00000000-0000-0000-0000-000000000001",
            name="test_agent",
            display_name="Test Agent",
            agent_type="general",
            graph_definition={
                "nodes": [
                    {"id": "input", "type": "input", "name": "Input"},
                    {"id": "llm", "type": "llm", "name": "LLM"},
                    {"id": "output", "type": "output", "name": "Output"}
                ],
                "edges": [
                    {"from": "START", "to": "input"},
                    {"from": "input", "to": "llm"},
                    {"from": "llm", "to": "output"},
                    {"from": "output", "to": "END"}
                ],
                "entry_point": "input"
            },
            system_prompt="Test prompt",
            tenant_id="00000000-0000-0000-0000-000000000001"
        )
    
    def test_load_agent_success(self, loader, simple_agent):
        """Test successful agent loading."""
        graph = loader.load_agent(simple_agent)
        
        # Verify graph is compiled
        assert graph is not None
        assert hasattr(graph, "invoke")
    
    def test_load_agent_with_invalid_definition(self, loader):
        """Test loading agent with invalid definition."""
        agent = Agent(
            id="00000000-0000-0000-0000-000000000001",
            name="invalid_agent",
            display_name="Invalid Agent",
            agent_type="general",
            graph_definition={"invalid": "definition"},
            tenant_id="00000000-0000-0000-0000-000000000001"
        )
        
        with pytest.raises(ValidationError):
            loader.load_agent(agent)
    
    def test_validate_agent_definition(self, loader):
        """Test agent definition validation."""
        # Valid definition
        valid_def = {
            "nodes": [
                {"id": "input", "type": "input", "name": "Input"}
            ],
            "edges": [],
            "entry_point": "input"
        }
        
        errors = loader.validate_agent_definition(valid_def)
        assert len(errors) == 0
        
        # Invalid definition
        invalid_def = {"invalid": "definition"}
        errors = loader.validate_agent_definition(invalid_def)
        assert len(errors) > 0
    
    def test_check_for_cycles(self, loader):
        """Test cycle detection in graph."""
        # Graph with cycle
        cyclic_def = {
            "nodes": [
                {"id": "a", "type": "input", "name": "A"},
                {"id": "b", "type": "llm", "name": "B"},
                {"id": "c", "type": "llm", "name": "C"}
            ],
            "edges": [
                {"from": "a", "to": "b"},
                {"from": "b", "to": "c"},
                {"from": "c", "to": "a"}  # Creates cycle
            ],
            "entry_point": "a"
        }
        
        errors = loader.validate_agent_definition(cyclic_def)
        assert any("cycle" in error.lower() for error in errors)


class TestDefaultAgentDefinitions:
    """Test default agent definitions."""
    
    def test_create_default_definitions(self):
        """Test creating default agent definitions."""
        defaults = create_default_agent_definitions()
        
        assert "qa_agent" in defaults
        assert "tool_agent" in defaults
        
        # Validate each default definition
        parser = GraphDefinitionParser()
        for name, definition in defaults.items():
            # Should not raise
            parser.parse(definition)
    
    def test_qa_agent_structure(self):
        """Test Q&A agent structure."""
        defaults = create_default_agent_definitions()
        qa_def = defaults["qa_agent"]
        
        # Check nodes
        node_types = {node["type"] for node in qa_def["nodes"]}
        assert "input" in node_types
        assert "llm" in node_types
        assert "output" in node_types
        
        # Check metadata
        assert "description" in qa_def["metadata"]
        assert "version" in qa_def["metadata"]
    
    def test_tool_agent_structure(self):
        """Test tool-using agent structure."""
        defaults = create_default_agent_definitions()
        tool_def = defaults["tool_agent"]
        
        # Check nodes
        node_types = {node["type"] for node in tool_def["nodes"]}
        assert "input" in node_types
        assert "llm" in node_types
        assert "tool" in node_types
        assert "condition" in node_types
        assert "output" in node_types
        
        # Check for conditional routing
        has_conditional = any(
            "condition" in edge
            for edge in tool_def["edges"]
        )
        assert has_conditional