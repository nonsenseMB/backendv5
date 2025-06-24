# Task 208: Basic Conversation UI Components

## Task Overview
**Sprint**: 200  
**Priority**: Medium  
**Effort**: 4 days  
**Dependencies**: 
- WebSocket implementation (Task 203)
- Conversation API (Task 202)
- Frontend framework setup

## ⚠️ IMPORTANT INSTRUCTIONS

### Before Starting Development:
1. **ALWAYS check existing database models** in `/docs/database/DATABASE_MODELS_V5_COMPLETE.md`
2. **NEVER create new models** without verifying if they already exist
3. **ALWAYS check existing API endpoints** before creating new ones
4. **ALWAYS check existing factories and services** before creating new ones
5. **NO MOCKS** - implement production-ready code
6. **NO PSEUDOCODE** - complete all implementations
7. **NO TODOs** - finish all tasks completely

### Required Reading:
- Frontend framework documentation (React/Next.js)
- WebSocket client libraries
- UI/UX best practices

## Task Description
Create the basic frontend components for the conversation system, including conversation list, chat interface, message streaming, and model selection. This provides the minimal UI needed to test the backend functionality.

## Frontend Architecture

### Technology Stack:
- **Framework**: React with Next.js (or existing choice)
- **State Management**: Zustand or Redux Toolkit
- **WebSocket**: Native WebSocket API or Socket.io-client
- **Styling**: Tailwind CSS or existing system
- **UI Components**: Radix UI or existing library

## Component Structure

### 1. Conversation List Component
```typescript
// components/conversations/ConversationList.tsx
```

Features:
- List active/archived conversations
- Show conversation title and last message
- Creation timestamp
- Agent/model indicator
- Team indicator for team conversations
- Search/filter functionality

Props:
```typescript
interface ConversationListProps {
  status?: 'active' | 'archived';
  teamId?: string;
  onSelect: (conversationId: string) => void;
}
```

### 2. Chat Interface Component
```typescript
// components/chat/ChatInterface.tsx
```

Main container with:
- Message list
- Input area
- Header with conversation info
- Token counter
- Agent indicator

Sub-components:
- `ChatHeader` - Title, agent, settings
- `MessageList` - Scrollable message area
- `Message` - Individual message display
- `ChatInput` - Text input with send button
- `TokenCounter` - Usage indicator

### 3. Message Streaming Component
```typescript
// components/chat/StreamingMessage.tsx
```

Handle streaming responses:
- Show typing indicator
- Append text as it arrives
- Show tool calls in progress
- Error state handling

States:
- `waiting` - Waiting for response
- `streaming` - Receiving tokens
- `complete` - Message finished
- `error` - Something went wrong

### 4. Model/Agent Selector
```typescript
// components/chat/AgentSelector.tsx
```

Features:
- Dropdown with available agents
- Show agent type and description
- Default agent indicator
- Team agent badge

### 5. New Conversation Modal
```typescript
// components/conversations/NewConversationModal.tsx
```

Fields:
- Title (optional)
- Agent selection
- Team selection (if applicable)
- Initial message (optional)

## State Management

### 1. Conversation Store
```typescript
// stores/conversationStore.ts
```

State structure:
```typescript
interface ConversationStore {
  conversations: Conversation[];
  activeConversation: Conversation | null;
  loading: boolean;
  error: string | null;
  
  // Actions
  fetchConversations: () => Promise<void>;
  createConversation: (data: CreateConversationData) => Promise<void>;
  selectConversation: (id: string) => void;
  archiveConversation: (id: string) => Promise<void>;
}
```

### 2. Chat Store
```typescript
// stores/chatStore.ts
```

State structure:
```typescript
interface ChatStore {
  messages: Message[];
  streaming: boolean;
  streamingMessage: Partial<Message> | null;
  
  // Actions
  sendMessage: (content: string) => Promise<void>;
  loadMessages: (conversationId: string) => Promise<void>;
  appendStreamChunk: (chunk: string) => void;
  completeStream: (finalMessage: Message) => void;
}
```

### 3. WebSocket Store
```typescript
// stores/websocketStore.ts
```

Manage WebSocket connection:
```typescript
interface WebSocketStore {
  connected: boolean;
  reconnecting: boolean;
  error: string | null;
  
  // Actions
  connect: () => void;
  disconnect: () => void;
  send: (event: any) => void;
  subscribe: (channel: Channel) => void;
}
```

## WebSocket Integration

### 1. WebSocket Hook
```typescript
// hooks/useWebSocket.ts
```

Custom hook for WebSocket:
```typescript
function useWebSocket() {
  const { token } = useAuth();
  const ws = useRef<WebSocket | null>(null);
  
  useEffect(() => {
    // Connect with JWT
    ws.current = new WebSocket(`${WS_URL}?token=${token}`);
    
    // Handle events
    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      handleWebSocketEvent(data);
    };
    
    return () => ws.current?.close();
  }, [token]);
  
  return {
    send: (data: any) => ws.current?.send(JSON.stringify(data)),
    connected: ws.current?.readyState === WebSocket.OPEN
  };
}
```

### 2. Event Handlers
```typescript
// utils/websocketHandlers.ts
```

Handle different event types:
```typescript
const eventHandlers = {
  'assistant.content': (data) => {
    chatStore.appendStreamChunk(data.content);
  },
  'assistant.complete': (data) => {
    chatStore.completeStream(data);
  },
  'tool.call.start': (data) => {
    chatStore.showToolCall(data);
  },
  // ... more handlers
};
```

## UI/UX Patterns

### 1. Loading States
- Skeleton screens for lists
- Shimmer effects for messages
- Progress indicators for uploads

### 2. Error Handling
- Toast notifications for errors
- Inline error messages
- Retry mechanisms
- Fallback UI

### 3. Responsive Design
- Mobile-first approach
- Collapsible sidebar on mobile
- Touch-friendly controls
- Appropriate font sizes

### 4. Accessibility
- ARIA labels
- Keyboard navigation
- Screen reader support
- Focus management

## Styling Guidelines

### 1. Color Scheme
```css
:root {
  --primary: #0066cc;
  --secondary: #6c757d;
  --success: #28a745;
  --danger: #dc3545;
  --warning: #ffc107;
  --info: #17a2b8;
  
  --bg-primary: #ffffff;
  --bg-secondary: #f8f9fa;
  --text-primary: #212529;
  --text-secondary: #6c757d;
}
```

### 2. Component Styling
- Consistent spacing (8px grid)
- Rounded corners (4px, 8px)
- Subtle shadows
- Smooth transitions

## Performance Optimizations

### 1. Message Virtualization
```typescript
// Use react-window for long message lists
import { VariableSizeList } from 'react-window';
```

### 2. Debounced Updates
- Debounce typing indicators
- Throttle scroll events
- Batch state updates

### 3. Code Splitting
```typescript
// Lazy load heavy components
const ChatInterface = lazy(() => import('./ChatInterface'));
```

## Testing Components

### 1. Unit Tests
```typescript
// __tests__/ConversationList.test.tsx
```

Test:
- Component rendering
- User interactions
- State updates
- Error states

### 2. Integration Tests
```typescript
// __tests__/ChatFlow.test.tsx
```

Test:
- Full conversation flow
- WebSocket integration
- Message sending/receiving
- Error recovery

### 3. E2E Tests
```typescript
// cypress/e2e/conversation.cy.ts
```

Test:
- Create conversation
- Send messages
- Receive responses
- Archive conversation

## Build Configuration

### 1. Environment Variables
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_APP_NAME=nAI Platform
```

### 2. TypeScript Configuration
```json
{
  "compilerOptions": {
    "strict": true,
    "target": "es2017",
    "lib": ["dom", "es2017"],
    "jsx": "react-jsx"
  }
}
```

## Success Criteria

- [ ] Conversation list functional
- [ ] Messages display correctly
- [ ] Streaming works smoothly
- [ ] WebSocket reconnection handled
- [ ] Error states user-friendly
- [ ] Mobile responsive
- [ ] Accessibility standards met
- [ ] Performance targets achieved

## Component Examples

### Message Component
```tsx
<Message
  role="assistant"
  content="Hello! How can I help you today?"
  timestamp={new Date()}
  streaming={false}
  agent={{
    name: "General Assistant",
    type: "general"
  }}
/>
```

### Token Counter
```tsx
<TokenCounter
  used={1234}
  limit={100000}
  cost={0.0234}
/>
```

## Future Enhancements

Consider for later:
1. Voice input/output
2. File attachments UI
3. Message reactions
4. Thread view
5. Export conversations
6. Keyboard shortcuts
7. Dark mode
8. Internationalization