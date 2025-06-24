"""
Dynamic agent loader with JSON graph definition parsing.
"""
import json
from typing import Any, Dict, List, Optional, Type

from langchain_core.language_models import BaseLLM
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from langgraph.graph import StateGraph, END
from langgraph.graph.graph import CompiledGraph
from langgraph.prebuilt import ToolNode

from src.agents.nodes import (
    ConditionNode,
    InputNode,
    LLMNode,
    MemoryNode,
    OutputNode
)
from src.agents.exceptions import ValidationError
from src.core.logging import get_logger
from src.infrastructure.database.models.agent import Agent

logger = get_logger(__name__)


class GraphDefinitionParser:
    """Parser for JSON graph definitions."""
    
    def __init__(self):
        self.node_types = {
            "input": InputNode,
            "llm": LLMNode,
            "tool": ToolNode,
            "condition": ConditionNode,
            "memory": MemoryNode,
            "output": OutputNode
        }
    
    def parse(self, definition: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and validate a graph definition."""
        # Validate required fields
        required_fields = ["nodes", "edges", "entry_point"]
        for field in required_fields:
            if field not in definition:
                raise ValidationError(f"Graph definition missing required field: {field}")
        
        # Validate nodes
        nodes = definition["nodes"]
        if not isinstance(nodes, list) or len(nodes) == 0:
            raise ValidationError("Graph definition must have at least one node")
        
        for node in nodes:
            self._validate_node(node)
        
        # Validate edges
        edges = definition["edges"]
        if not isinstance(edges, list):
            raise ValidationError("Edges must be a list")
        
        node_ids = {node["id"] for node in nodes}
        for edge in edges:
            self._validate_edge(edge, node_ids)
        
        # Validate entry point
        if definition["entry_point"] not in node_ids:
            raise ValidationError(f"Entry point '{definition['entry_point']}' not found in nodes")
        
        return definition
    
    def _validate_node(self, node: Dict[str, Any]):
        """Validate a single node definition."""
        required_fields = ["id", "type", "name"]
        for field in required_fields:
            if field not in node:
                raise ValidationError(f"Node missing required field: {field}")
        
        if node["type"] not in self.node_types:
            raise ValidationError(f"Unknown node type: {node['type']}")
        
        # Validate node-specific config
        if "config" in node and not isinstance(node["config"], dict):
            raise ValidationError("Node config must be a dictionary")
    
    def _validate_edge(self, edge: Dict[str, Any], node_ids: set):
        """Validate a single edge definition."""
        required_fields = ["from", "to"]
        for field in required_fields:
            if field not in edge:
                raise ValidationError(f"Edge missing required field: {field}")
        
        if edge["from"] not in node_ids and edge["from"] != "START":
            raise ValidationError(f"Edge 'from' references unknown node: {edge['from']}")
        
        if edge["to"] not in node_ids and edge["to"] != "END":
            raise ValidationError(f"Edge 'to' references unknown node: {edge['to']}")


class AgentState:
    """State for agent execution."""
    
    def __init__(self):
        self.messages: List[Any] = []
        self.context: Dict[str, Any] = {}
        self.memory: Dict[str, Any] = {}
        self.tools_output: Dict[str, Any] = {}
        self.current_node: Optional[str] = None
        self.execution_path: List[str] = []
        self.error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary."""
        return {
            "messages": [self._serialize_message(msg) for msg in self.messages],
            "context": self.context,
            "memory": self.memory,
            "tools_output": self.tools_output,
            "current_node": self.current_node,
            "execution_path": self.execution_path,
            "error": self.error
        }
    
    def _serialize_message(self, message) -> Dict[str, Any]:
        """Serialize a message object."""
        if isinstance(message, (HumanMessage, AIMessage, SystemMessage)):
            return {
                "type": message.__class__.__name__,
                "content": message.content,
                "additional_kwargs": message.additional_kwargs
            }
        return message


class AgentLoader:
    """Loader for creating agent graphs from definitions."""
    
    def __init__(
        self,
        llm_provider: BaseLLM,
        tools_registry: Dict[str, BaseTool] = None
    ):
        self.llm_provider = llm_provider
        self.tools_registry = tools_registry or {}
        self.parser = GraphDefinitionParser()
    
    def load_agent(self, agent: Agent) -> CompiledGraph:
        """Load an agent from its definition."""
        # Parse graph definition
        definition = self.parser.parse(agent.graph_definition)
        
        # Create state graph
        graph = StateGraph(AgentState)
        
        # Build nodes
        nodes = self._build_nodes(definition["nodes"], agent)
        
        # Add nodes to graph
        for node_id, node_instance in nodes.items():
            graph.add_node(node_id, node_instance)
        
        # Add edges
        for edge in definition["edges"]:
            if "condition" in edge:
                # Conditional edge
                condition_fn = self._build_condition(edge["condition"])
                graph.add_conditional_edges(
                    edge["from"],
                    condition_fn,
                    edge["routes"]
                )
            else:
                # Simple edge
                if edge["from"] == "START":
                    graph.set_entry_point(edge["to"])
                elif edge["to"] == "END":
                    graph.add_edge(edge["from"], END)
                else:
                    graph.add_edge(edge["from"], edge["to"])
        
        # Set entry point if not already set by edges
        if "entry_point" in definition and definition["entry_point"]:
            graph.set_entry_point(definition["entry_point"])
        
        # Compile the graph
        compiled = graph.compile()
        
        logger.info(
            "Loaded agent graph",
            agent_id=str(agent.id),
            agent_name=agent.name,
            node_count=len(nodes),
            edge_count=len(definition["edges"])
        )
        
        return compiled
    
    def _build_nodes(
        self,
        node_definitions: List[Dict[str, Any]],
        agent: Agent
    ) -> Dict[str, Runnable]:
        """Build node instances from definitions."""
        nodes = {}
        
        for node_def in node_definitions:
            node_type = node_def["type"]
            node_config = node_def.get("config", {})
            
            # Create node based on type
            if node_type == "input":
                node = InputNode(config=node_config)
            elif node_type == "llm":
                node = LLMNode(
                    llm=self.llm_provider,
                    system_prompt=agent.system_prompt,
                    config=node_config
                )
            elif node_type == "tool":
                tools = self._get_tools_for_node(node_config.get("tool_ids", []))
                node = ToolNode(tools=tools)
            elif node_type == "condition":
                node = ConditionNode(config=node_config)
            elif node_type == "memory":
                node = MemoryNode(
                    agent_id=agent.id,
                    config=node_config
                )
            elif node_type == "output":
                node = OutputNode(config=node_config)
            else:
                raise ValidationError(f"Unknown node type: {node_type}")
            
            nodes[node_def["id"]] = node
        
        return nodes
    
    def _get_tools_for_node(self, tool_ids: List[str]) -> List[BaseTool]:
        """Get tool instances for a node."""
        tools = []
        
        for tool_id in tool_ids:
            if tool_id in self.tools_registry:
                tools.append(self.tools_registry[tool_id])
            else:
                logger.warning(f"Tool not found in registry: {tool_id}")
        
        return tools
    
    def _build_condition(self, condition_config: Dict[str, Any]) -> callable:
        """Build a condition function from configuration."""
        condition_type = condition_config.get("type", "simple")
        
        if condition_type == "simple":
            # Simple key-value comparison
            key = condition_config["key"]
            operator = condition_config.get("operator", "equals")
            value = condition_config["value"]
            
            def condition_fn(state: AgentState) -> str:
                state_value = state.context.get(key)
                
                if operator == "equals":
                    result = state_value == value
                elif operator == "not_equals":
                    result = state_value != value
                elif operator == "contains":
                    result = value in str(state_value)
                elif operator == "greater_than":
                    result = float(state_value) > float(value)
                elif operator == "less_than":
                    result = float(state_value) < float(value)
                else:
                    result = False
                
                return "true" if result else "false"
            
            return condition_fn
        
        elif condition_type == "custom":
            # Custom condition function
            # This would typically load a predefined condition function
            condition_name = condition_config["name"]
            return self._get_custom_condition(condition_name)
        
        else:
            raise ValidationError(f"Unknown condition type: {condition_type}")
    
    def _get_custom_condition(self, name: str) -> callable:
        """Get a custom condition function by name."""
        # Placeholder for custom condition registry
        custom_conditions = {
            "has_tool_output": lambda state: "true" if state.tools_output else "false",
            "has_error": lambda state: "true" if state.error else "false",
            "message_count_exceeds": lambda state: "true" if len(state.messages) > 10 else "false"
        }
        
        if name not in custom_conditions:
            raise ValidationError(f"Unknown custom condition: {name}")
        
        return custom_conditions[name]
    
    def validate_agent_definition(self, definition: Dict[str, Any]) -> List[str]:
        """Validate an agent definition and return any errors."""
        errors = []
        
        try:
            self.parser.parse(definition)
        except ValidationError as e:
            errors.append(str(e))
        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")
        
        # Additional validation
        if "metadata" in definition:
            if not isinstance(definition["metadata"], dict):
                errors.append("Metadata must be a dictionary")
        
        # Check for circular dependencies
        if not errors:
            cycles = self._check_for_cycles(definition)
            if cycles:
                errors.append(f"Graph contains cycles: {cycles}")
        
        return errors
    
    def _check_for_cycles(self, definition: Dict[str, Any]) -> List[List[str]]:
        """Check for cycles in the graph definition."""
        # Build adjacency list
        graph = {}
        for node in definition["nodes"]:
            graph[node["id"]] = []
        
        for edge in definition["edges"]:
            if edge["from"] != "START" and edge["to"] != "END":
                if edge["from"] in graph:
                    graph[edge["from"]].append(edge["to"])
        
        # Find cycles using DFS
        cycles = []
        visited = set()
        rec_stack = set()
        path = []
        
        def dfs(node):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
                    return True
            
            path.pop()
            rec_stack.remove(node)
            return False
        
        for node in graph:
            if node not in visited:
                dfs(node)
        
        return cycles


# Example usage for creating default agent definitions
def create_default_agent_definitions() -> Dict[str, Dict[str, Any]]:
    """Create default agent graph definitions."""
    
    # Simple Q&A Agent
    qa_agent = {
        "nodes": [
            {
                "id": "input",
                "type": "input",
                "name": "User Input"
            },
            {
                "id": "llm",
                "type": "llm",
                "name": "LLM Response",
                "config": {
                    "temperature": 0.7,
                    "max_tokens": 500
                }
            },
            {
                "id": "output",
                "type": "output",
                "name": "Agent Output"
            }
        ],
        "edges": [
            {"from": "START", "to": "input"},
            {"from": "input", "to": "llm"},
            {"from": "llm", "to": "output"},
            {"from": "output", "to": "END"}
        ],
        "entry_point": "input",
        "metadata": {
            "description": "Simple Q&A agent for general queries",
            "version": "1.0.0"
        }
    }
    
    # Tool-using Agent
    tool_agent = {
        "nodes": [
            {
                "id": "input",
                "type": "input",
                "name": "User Input"
            },
            {
                "id": "llm_plan",
                "type": "llm",
                "name": "Plan Generation",
                "config": {
                    "prompt_template": "Given the user query, determine which tools to use."
                }
            },
            {
                "id": "condition",
                "type": "condition",
                "name": "Needs Tools?",
                "config": {
                    "type": "custom",
                    "name": "has_tool_output"
                }
            },
            {
                "id": "tools",
                "type": "tool",
                "name": "Tool Execution",
                "config": {
                    "tool_ids": ["web_search", "calculator", "code_executor"]
                }
            },
            {
                "id": "llm_final",
                "type": "llm",
                "name": "Final Response",
                "config": {
                    "prompt_template": "Based on the tool outputs, provide a final response."
                }
            },
            {
                "id": "output",
                "type": "output",
                "name": "Agent Output"
            }
        ],
        "edges": [
            {"from": "START", "to": "input"},
            {"from": "input", "to": "llm_plan"},
            {
                "from": "llm_plan",
                "to": "condition",
                "condition": {
                    "type": "custom",
                    "name": "has_tool_output"
                },
                "routes": {
                    "true": "tools",
                    "false": "llm_final"
                }
            },
            {"from": "tools", "to": "llm_final"},
            {"from": "llm_final", "to": "output"},
            {"from": "output", "to": "END"}
        ],
        "entry_point": "input",
        "metadata": {
            "description": "Agent that can use tools to answer queries",
            "version": "1.0.0"
        }
    }
    
    return {
        "qa_agent": qa_agent,
        "tool_agent": tool_agent
    }