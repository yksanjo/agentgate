# AgentGate

**Agent Authentication Service** - Identity and authentication for AI agents.

Part of the Agent Infrastructure Stack:
- **AgentGate** (this repo) - Authentication
- [AgentMem](https://github.com/yksanjo/agentmem) - Memory/State
- [AgentLens](https://github.com/yksanjo/agentlens) - Observability

## Features

- **Agent Identity Management** - Create and manage AI agent identities
- **API Key Authentication** - Secure API key generation with rotation
- **JWT Tokens** - Short-lived tokens for authenticated sessions
- **Capability-Based Permissions** - Fine-grained access control
- **Agent-to-Agent Auth** - Secure communication between agents
- **Human Delegation** - Humans can delegate authority to agents
- **Audit Logging** - Track all authentication events

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yksanjo/agentgate.git
cd agentgate

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export AGENTGATE_SECRET_KEY="your-secret-key-here"
export SUPABASE_URL="your-project.supabase.co"  # Optional
export SUPABASE_SERVICE_ROLE_KEY="your-key"     # Optional

# Run the server
uvicorn api.main:app --reload
```

### Using the SDK

```python
from agentgate import AgentAuth

# Initialize with API key
auth = AgentAuth(api_key="ag_xxx...")

# Get agent ID
print(f"Agent ID: {auth.agent_id}")

# Get a JWT token
token = auth.get_token(scopes=["memory:read", "memory:write"])

# Verify another agent
other_agent = auth.verify_agent(agent_id="...")
```

## API Endpoints

### Agents

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/agents` | POST | Create new agent |
| `/api/v1/agents` | GET | List agents |
| `/api/v1/agents/{id}` | GET | Get agent by ID |
| `/api/v1/agents/{id}` | PATCH | Update agent |
| `/api/v1/agents/{id}` | DELETE | Delete agent |

### API Keys

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/keys` | POST | Create API key |
| `/api/v1/keys/agent/{id}` | GET | List keys for agent |
| `/api/v1/keys/{id}` | DELETE | Revoke key |
| `/api/v1/keys/{id}/rotate` | POST | Rotate key |

### Tokens

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/tokens` | POST | Create JWT token |
| `/api/v1/tokens/from-key` | POST | Exchange key for token |
| `/api/v1/tokens/refresh` | POST | Refresh token |
| `/api/v1/tokens/revoke` | POST | Revoke token |

### Verification

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/verify/token` | POST | Verify JWT token |
| `/api/v1/verify/key` | POST | Verify API key |

### Audit

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/audit` | GET | Query audit logs |
| `/api/v1/audit/agent/{id}` | GET | Get agent activity |
| `/api/v1/audit/failures` | GET | Get auth failures |

## Authentication

### API Key

```bash
curl -X POST https://agentgate.railway.app/api/v1/tokens \
  -H "X-API-Key: ag_xxx..." \
  -H "Content-Type: application/json" \
  -d '{"scopes": ["memory:read"]}'
```

### Bearer Token

```bash
curl https://agentgate.railway.app/api/v1/agents \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

## Permission Scopes

Scopes follow the pattern `resource:action`:

- `*` - Full access to everything
- `agents:read` - Read agent information
- `agents:write` - Create/update agents
- `agents:delete` - Delete agents
- `keys:read` - View API keys
- `keys:write` - Create/rotate keys
- `keys:delete` - Revoke keys
- `memory:read` - Read memories (for AgentMem)
- `memory:write` - Write memories
- `traces:read` - Read traces (for AgentLens)
- `traces:write` - Write traces
- `audit:read` - Read audit logs
- `audit:admin` - Admin audit access

## Database Schema

AgentGate uses Supabase (PostgreSQL) for persistence:

```sql
-- Agent identities
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id UUID,
    capabilities JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- API keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    name VARCHAR(255),
    scopes JSONB DEFAULT '["*"]',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id),
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(255),
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Deployment

### Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AGENTGATE_SECRET_KEY` | Yes | JWT signing secret |
| `SUPABASE_URL` | No | Supabase project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | No | Supabase service key |
| `CORS_ORIGINS` | No | Allowed CORS origins |
| `PORT` | No | Server port (default: 8000) |

## Integration with Other Services

### AgentMem (Memory)

AgentGate provides authentication for AgentMem:

```python
from agentgate import AgentAuth
from agentmem import Memory

auth = AgentAuth(api_key="ag_xxx...")
memory = Memory(
    agent_id=auth.agent_id,
    auth_token=auth.token
)
```

### AgentLens (Observability)

AgentGate provides authentication for AgentLens:

```python
from agentgate import AgentAuth
from agentlens import trace

auth = AgentAuth(api_key="ag_xxx...")

@trace(auth=auth)
async def my_agent_function():
    ...
```

## License

MIT License - see LICENSE file.
