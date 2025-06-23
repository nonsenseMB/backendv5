# API Documentation Guide

## FastAPI Integration

### Basic Endpoint Documentation

```python
from fastapi import FastAPI, Path, Query, Body
from pydantic import BaseModel, Field
from typing import Optional, List

@app.post(
    "/api/v1/messages",
    summary="Send a message",
    description="""
    Send a message in a conversation.
    
    The message will be processed by the AI and a response
    will be generated. Long messages may be truncated.
    """,
    response_description="The created message with AI response",
    responses={
        201: {"description": "Message created successfully"},
        400: {"description": "Invalid request"},
        401: {"description": "Not authenticated"},
        429: {"description": "Rate limit exceeded"},
    },
    tags=["chat"]
)
async def send_message(request: MessageRequest):
    """Endpoint implementation."""
    pass
```

### Request/Response Models

```python
class MessageRequest(BaseModel):
    """Request model for sending a message."""
    
    content: str = Field(
        ...,
        description="The message content",
        min_length=1,
        max_length=4000,
        example="What's the weather like today?"
    )
    
    conversation_id: UUID = Field(
        ...,
        description="ID of the conversation",
        example="123e4567-e89b-12d3-a456-426614174000"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "content": "Can you help me with Python?",
                "conversation_id": "123e4567-e89b-12d3-a456-426614174000"
            }
        }
```

## OpenAPI Configuration

```python
app = FastAPI(
    title="nAI Backend API",
    description="""
    AI-powered chat system with advanced memory capabilities.

    ## Features
    - 🤖 Multi-model AI support
    - 🧠 Long-term memory
    - 🔍 Semantic search
    - 🔐 OAuth2 authentication
    """,
    version="5.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)
```

## API Client Examples

### Python Client

```python
import httpx
from typing import Optional

class NAIClient:
    """Client for nAI Backend API."""
    
    def __init__(self, api_key: str, base_url: str = "https://api.example.com"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {api_key}"}
    
    async def send_message(self, content: str, conversation_id: str):
        """Send a message to the API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/messages",
                headers=self.headers,
                json={"content": content, "conversation_id": conversation_id}
            )
            response.raise_for_status()
            return response.json()
```

### cURL Examples

```bash
# Send a message
curl -X POST "https://api.example.com/api/v1/messages" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Hello!",
    "conversation_id": "123e4567-e89b-12d3-a456-426614174000"
  }'

# Get conversation history
curl -X GET "https://api.example.com/api/v1/conversations/123e4567-e89b-12d3-a456-426614174000" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## API Versioning

### URL Path Versioning

```python
# v1 routes
app.include_router(v1_router, prefix="/api/v1")

# v2 routes (future)
app.include_router(v2_router, prefix="/api/v2")
```

### Header Versioning

```python
@app.get("/api/resource")
async def get_resource(api_version: Optional[str] = Header(default="v1")):
    if api_version == "v2":
        return {"data": "v2 response"}
    return {"data": "v1 response"}
```

## Testing API Documentation

```python
# tests/test_api_docs.py
def test_openapi_schema(client):
    """Test that OpenAPI schema is valid."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    
    schema = response.json()
    assert schema["info"]["title"] == "nAI Backend API"
    assert "paths" in schema
    assert "/api/v1/messages" in schema["paths"]
```