# Custom Agent Configuration for Proxychains-Windows

This directory contains custom agent definitions that can be used with GitHub Copilot and MCP-compatible tools.

## Available Agents

### 1. Proxychains Developer Agent
**File**: `proxychains-developer.md`  
**Purpose**: Expert Windows systems developer for implementing features from TODO.md

**Capabilities**:
- Understands Win32 API and DLL injection
- Can implement proxy protocols (SOCKS5, HTTP)
- Handles x86/x64 architecture differences
- Writes proper error handling and logging
- Updates documentation automatically

**How to Use**:

#### With GitHub Copilot
In your IDE, ask Copilot to follow the agent guidelines:
```
Following the proxychains developer guidelines in .github/agents/proxychains-developer.md,
implement [feature name] from TODO.md
```

#### With MCP Task Tool
Delegate to the general-purpose agent:
```
@task
  agent_type: general-purpose
  description: "Implement feature from TODO"
  prompt: |
    You are an expert Windows systems developer working on proxychains-windows.
    
    Read and follow the guidelines in:
    - .github/agents/proxychains-developer.md (agent capabilities)
    - .github/copilot-instructions.md (project conventions)
    - TODO.md (feature requirements)
    
    Implement [specific feature] following all project conventions.
    Update TODO.md to mark the feature as complete.
```

#### With Custom Tool Integration
If integrating with custom tooling:
```json
{
  "agent": "proxychains-developer",
  "config_path": ".github/agents/proxychains-developer.md",
  "task": "implement-feature",
  "feature": "dynamic-chain-support",
  "source": "TODO.md"
}
```

## Agent Workflow

### Standard Feature Implementation Flow

1. **Read Feature Requirements**
   - Agent reads TODO.md
   - Identifies priority and difficulty
   - Notes dependencies and affected files

2. **Analyze Existing Code**
   - Uses `grep` to find related implementations
   - Reviews similar features
   - Understands current architecture

3. **Propose Implementation Plan**
   - Lists files to modify
   - Describes changes needed
   - Identifies test scenarios
   - Requests approval

4. **Implement Changes**
   - Modifies source files
   - Adds configuration parsing
   - Implements error handling
   - Adds logging

5. **Update Documentation**
   - Marks TODO.md item as complete
   - Updates CHANGELOG.md
   - Updates README.md if user-facing
   - Adds tests to TESTING.md

6. **Validate**
   - Describes test scenarios
   - Lists what to verify
   - Notes potential issues

## MCP Tools Available to Agents

Agents have access to these MCP server capabilities:

### File Operations
- Read/write/edit files
- Search code with grep
- Find files with glob
- List directories

### Git Operations
- View history
- Check diffs
- List branches
- Review commits

### GitHub Operations
- Search code across repos
- Read files from GitHub
- Access commit history
- Review pull requests

### Task Delegation
- Delegate to specialized sub-agents
- Use explore agent for codebase questions
- Use code-review agent for validation

### Knowledge Management
- Store project insights
- Search stored knowledge
- Build context database

## Creating New Agents

To add a new specialized agent:

1. Create `your-agent-name.md` in this directory
2. Define agent identity and capabilities
3. Specify expertise areas
4. Document interaction patterns
5. Add usage examples
6. Update this README.md

### Agent Template

```markdown
# [Agent Name]

## Agent Identity
- Name: [descriptive name]
- Role: [specialized role]
- Version: 1.0

## Expertise Areas
- [Primary skill 1]
- [Primary skill 2]
- ...

## Capabilities
[What this agent can do]

## Usage
[How to invoke this agent]

## Working Context
[What the agent needs to know]

## Implementation Guidelines
[How the agent should work]
```

## Agent Best Practices

### For Agent Developers

1. **Clear Scope** - Define what the agent can and cannot do
2. **Context Awareness** - Ensure agent understands project structure
3. **Error Handling** - Agent should handle failures gracefully
4. **Documentation** - Agent should auto-update docs
5. **Validation** - Agent should describe how to test its work

### For Users

1. **Specific Requests** - Be clear about what feature to implement
2. **Review Plans** - Always review the agent's implementation plan
3. **Test Thoroughly** - Agent cannot run tests, you must validate
4. **Provide Feedback** - Help improve agent by reporting issues

### For Integration

1. **Standard Format** - Follow GitHub Copilot instruction format
2. **MCP Compatible** - Use standard MCP tool references
3. **Version Control** - Keep agent definitions in git
4. **Documentation** - Update this README when adding agents

## Examples

### Example 1: Implement Dynamic Chain Support

```markdown
Prompt to Copilot:
"Following the proxychains developer guidelines, implement dynamic chain 
support from TODO.md. This should skip dead proxies and continue with 
alive ones."

Agent will:
1. Read TODO.md for requirements
2. Find related code in hook_connect_win32.c
3. Propose adding proxy state tracking
4. Implement skip logic for dead proxies
5. Update config parser for dynamic_chain option
6. Update TODO.md, CHANGELOG.md
7. Describe test scenarios
```

### Example 2: Add HTTP Proxy Support

```markdown
Using MCP task tool:

@task 
  agent_type: general-purpose
  description: "Add HTTP proxy support"
  prompt: |
    Following .github/agents/proxychains-developer.md:
    
    Implement HTTP/HTTPS proxy support from TODO.md:
    - Add PXCH_PROXY_TYPE_HTTP to defines
    - Implement HTTP CONNECT method
    - Add config parsing for http proxy type
    - Create Http_Connect and Http_Handshake functions
    - Update TODO.md when complete
    
Agent will implement full HTTP proxy support following all conventions.
```

### Example 3: Explore Codebase

```markdown
Using explore agent:

@task
  agent_type: explore
  description: "Understand proxy chain logic"
  prompt: |
    Explain how the proxy chain connection logic works in 
    proxychains-windows. Focus on Ws2_32_LoopThroughProxyChain 
    function and how it handles multiple proxies.

Agent will provide focused explanation under 300 words.
```

## Integration with CI/CD

The `.github/workflows/copilot-setup.yml` workflow:
- Validates agent configuration files
- Ensures TODO.md is properly formatted
- Generates agent capability reports
- Verifies development environment

Run manually: `gh workflow run copilot-setup.yml`

## Support

For questions about agents:
- Review `.github/copilot-instructions.md` for project conventions
- Check `TODO.md` for current feature list
- See `TESTING.md` for validation procedures
- Open GitHub issue for help

---

**Note**: These agents are designed to work with GitHub Copilot and MCP-compatible tools. They provide context and guidelines but require human oversight and testing.
