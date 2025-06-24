"""
Default system agents and configurations.
"""
from typing import Dict, Any


def get_research_agent_definition() -> Dict[str, Any]:
    """Get definition for research agent that can search and analyze information."""
    return {
        "nodes": [
            {
                "id": "input",
                "type": "input",
                "name": "User Query"
            },
            {
                "id": "query_analysis",
                "type": "llm",
                "name": "Query Analysis",
                "config": {
                    "prompt_template": """Analyze the user's research query and determine:
1. What information is being requested
2. What tools might be needed (web search, document analysis, etc.)
3. How to best structure the research

User Query: {user_input}

Provide a structured analysis.""",
                    "temperature": 0.3
                }
            },
            {
                "id": "memory_check",
                "type": "memory",
                "name": "Check Memory",
                "config": {
                    "operation": "query",
                    "memory_type": "long_term"
                }
            },
            {
                "id": "need_search",
                "type": "condition",
                "name": "Need Search?",
                "config": {
                    "type": "custom",
                    "name": "needs_external_search"
                }
            },
            {
                "id": "web_search",
                "type": "tool",
                "name": "Web Search",
                "config": {
                    "tool_ids": ["web_search", "news_search"]
                }
            },
            {
                "id": "synthesis",
                "type": "llm",
                "name": "Synthesize Results",
                "config": {
                    "prompt_template": """Based on the research findings, provide a comprehensive answer:

Query: {user_input}
Memory Results: {memory_results}
Search Results: {search_results}

Synthesize this information into a clear, well-structured response.""",
                    "temperature": 0.5,
                    "max_tokens": 1000
                }
            },
            {
                "id": "save_memory",
                "type": "memory",
                "name": "Save to Memory",
                "config": {
                    "operation": "update",
                    "memory_type": "long_term"
                }
            },
            {
                "id": "output",
                "type": "output",
                "name": "Research Output",
                "config": {
                    "format": "markdown"
                }
            }
        ],
        "edges": [
            {"from": "START", "to": "input"},
            {"from": "input", "to": "query_analysis"},
            {"from": "query_analysis", "to": "memory_check"},
            {
                "from": "memory_check",
                "to": "need_search",
                "condition": {
                    "type": "custom",
                    "name": "needs_external_search"
                },
                "routes": {
                    "true": "web_search",
                    "false": "synthesis"
                }
            },
            {"from": "web_search", "to": "synthesis"},
            {"from": "synthesis", "to": "save_memory"},
            {"from": "save_memory", "to": "output"},
            {"from": "output", "to": "END"}
        ],
        "entry_point": "input",
        "metadata": {
            "description": "Research agent that can search, analyze, and synthesize information",
            "version": "1.0.0",
            "capabilities": ["web_search", "memory_access", "synthesis"],
            "tags": ["research", "analysis", "search"]
        }
    }


def get_coding_agent_definition() -> Dict[str, Any]:
    """Get definition for coding agent that can write and analyze code."""
    return {
        "nodes": [
            {
                "id": "input",
                "type": "input",
                "name": "Coding Request"
            },
            {
                "id": "task_analysis",
                "type": "llm",
                "name": "Analyze Task",
                "config": {
                    "prompt_template": """Analyze the coding task and determine:
1. Programming language required
2. Type of task (new code, debugging, refactoring, etc.)
3. Any specific requirements or constraints
4. Tools needed (code execution, file access, etc.)

Task: {user_input}

Provide structured analysis.""",
                    "temperature": 0.2
                }
            },
            {
                "id": "code_generation",
                "type": "llm",
                "name": "Generate Code",
                "config": {
                    "prompt_template": """Based on the task analysis, generate the required code:

Task: {user_input}
Analysis: {task_analysis}

Provide clean, well-commented code with explanations.""",
                    "temperature": 0.3,
                    "max_tokens": 2000
                }
            },
            {
                "id": "need_execution",
                "type": "condition",
                "name": "Need Execution?",
                "config": {
                    "type": "simple",
                    "key": "execute_code",
                    "operator": "equals",
                    "value": true
                }
            },
            {
                "id": "code_execution",
                "type": "tool",
                "name": "Execute Code",
                "config": {
                    "tool_ids": ["code_executor", "python_repl"]
                }
            },
            {
                "id": "error_check",
                "type": "condition",
                "name": "Has Errors?",
                "config": {
                    "type": "custom",
                    "name": "has_execution_errors"
                }
            },
            {
                "id": "fix_errors",
                "type": "llm",
                "name": "Fix Errors",
                "config": {
                    "prompt_template": """The code execution resulted in errors. Fix the issues:

Original Code: {generated_code}
Error: {execution_error}

Provide corrected code.""",
                    "temperature": 0.2
                }
            },
            {
                "id": "final_review",
                "type": "llm",
                "name": "Final Review",
                "config": {
                    "prompt_template": """Review the final code and provide:
1. Summary of what was implemented
2. Any important notes or warnings
3. Suggestions for improvement

Code: {final_code}
Execution Result: {execution_result}""",
                    "temperature": 0.4
                }
            },
            {
                "id": "output",
                "type": "output",
                "name": "Code Output",
                "config": {
                    "format": "markdown"
                }
            }
        ],
        "edges": [
            {"from": "START", "to": "input"},
            {"from": "input", "to": "task_analysis"},
            {"from": "task_analysis", "to": "code_generation"},
            {
                "from": "code_generation",
                "to": "need_execution",
                "condition": {
                    "type": "simple",
                    "key": "execute_code",
                    "operator": "equals",
                    "value": true
                },
                "routes": {
                    "true": "code_execution",
                    "false": "final_review"
                }
            },
            {
                "from": "code_execution",
                "to": "error_check",
                "condition": {
                    "type": "custom",
                    "name": "has_execution_errors"
                },
                "routes": {
                    "true": "fix_errors",
                    "false": "final_review"
                }
            },
            {"from": "fix_errors", "to": "code_execution"},
            {"from": "final_review", "to": "output"},
            {"from": "output", "to": "END"}
        ],
        "entry_point": "input",
        "metadata": {
            "description": "Coding agent that can write, debug, and execute code",
            "version": "1.0.0",
            "capabilities": ["code_generation", "code_execution", "debugging"],
            "tags": ["coding", "programming", "development"]
        }
    }


def get_coordinator_agent_definition() -> Dict[str, Any]:
    """Get definition for coordinator agent that delegates to other agents."""
    return {
        "nodes": [
            {
                "id": "input",
                "type": "input",
                "name": "Task Input"
            },
            {
                "id": "task_breakdown",
                "type": "llm",
                "name": "Break Down Task",
                "config": {
                    "prompt_template": """Analyze the task and break it down into subtasks:

Task: {user_input}

Determine:
1. What subtasks are needed
2. Which specialized agents should handle each subtask
3. The order of execution
4. How to combine results

Provide a structured plan.""",
                    "temperature": 0.4
                }
            },
            {
                "id": "select_agents",
                "type": "llm",
                "name": "Select Agents",
                "config": {
                    "prompt_template": """Based on the task breakdown, select appropriate agents:

Task Breakdown: {task_breakdown}
Available Agents: {available_agents}

Select the best agents for each subtask."""
                }
            },
            {
                "id": "delegate_tasks",
                "type": "tool",
                "name": "Delegate to Agents",
                "config": {
                    "tool_ids": ["agent_executor"]
                }
            },
            {
                "id": "monitor_progress",
                "type": "condition",
                "name": "Tasks Complete?",
                "config": {
                    "type": "custom",
                    "name": "all_tasks_complete"
                }
            },
            {
                "id": "combine_results",
                "type": "llm",
                "name": "Combine Results",
                "config": {
                    "prompt_template": """Combine the results from all subtasks:

Original Task: {user_input}
Subtask Results: {subtask_results}

Provide a comprehensive response that addresses the original task.""",
                    "temperature": 0.5,
                    "max_tokens": 1500
                }
            },
            {
                "id": "output",
                "type": "output",
                "name": "Final Output",
                "config": {
                    "format": "json"
                }
            }
        ],
        "edges": [
            {"from": "START", "to": "input"},
            {"from": "input", "to": "task_breakdown"},
            {"from": "task_breakdown", "to": "select_agents"},
            {"from": "select_agents", "to": "delegate_tasks"},
            {
                "from": "delegate_tasks",
                "to": "monitor_progress",
                "condition": {
                    "type": "custom",
                    "name": "all_tasks_complete"
                },
                "routes": {
                    "true": "combine_results",
                    "false": "delegate_tasks"
                }
            },
            {"from": "combine_results", "to": "output"},
            {"from": "output", "to": "END"}
        ],
        "entry_point": "input",
        "metadata": {
            "description": "Coordinator agent that breaks down complex tasks and delegates to specialized agents",
            "version": "1.0.0",
            "capabilities": ["task_breakdown", "agent_coordination", "result_synthesis"],
            "tags": ["coordinator", "manager", "delegation"]
        }
    }


def get_all_default_agents() -> Dict[str, Dict[str, Any]]:
    """Get all default agent definitions."""
    return {
        "research_agent": get_research_agent_definition(),
        "coding_agent": get_coding_agent_definition(),
        "coordinator_agent": get_coordinator_agent_definition()
    }


# Default agent configurations
DEFAULT_AGENT_CONFIGS = {
    "research_agent": {
        "display_name": "Research Assistant",
        "agent_type": "specialist",
        "specialization": "research",
        "system_prompt": """You are a research specialist AI assistant. Your role is to:
1. Understand research queries thoroughly
2. Search for relevant information from multiple sources
3. Analyze and synthesize findings
4. Present well-structured, factual responses
5. Cite sources when available
6. Acknowledge limitations and uncertainties

Always strive for accuracy and comprehensiveness in your research.""",
        "capabilities": ["web_search", "memory_access", "document_analysis"],
        "temperature": 0.5,
        "is_public": True
    },
    "coding_agent": {
        "display_name": "Coding Assistant",
        "agent_type": "specialist",
        "specialization": "coding",
        "system_prompt": """You are a coding specialist AI assistant. Your role is to:
1. Understand programming tasks and requirements
2. Write clean, efficient, and well-documented code
3. Follow best practices and coding standards
4. Debug and fix errors
5. Explain code clearly
6. Suggest improvements and optimizations

Support multiple programming languages and paradigms.""",
        "capabilities": ["code_generation", "code_execution", "debugging", "code_review"],
        "temperature": 0.3,
        "is_public": True
    },
    "coordinator_agent": {
        "display_name": "Task Coordinator",
        "agent_type": "coordinator",
        "system_prompt": """You are a coordination AI assistant. Your role is to:
1. Analyze complex tasks and break them into manageable subtasks
2. Identify the best specialized agents for each subtask
3. Coordinate execution across multiple agents
4. Monitor progress and handle dependencies
5. Combine results into cohesive responses
6. Ensure quality and completeness

Act as an effective project manager for AI agent teams.""",
        "capabilities": ["task_breakdown", "agent_coordination", "progress_monitoring"],
        "temperature": 0.4,
        "is_public": True
    }
}