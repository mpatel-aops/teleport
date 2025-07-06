# GitLab OAuth Implementation Plan for Teleport OSS

## Overview
This document outlines the implementation plan for adding GitLab OAuth authentication to Teleport OSS, following the same pattern as the existing GitHub OAuth implementation.

## Architecture Overview

GitLab OAuth will be implemented as a specific OAuth2 provider (not using the generic OIDC system) following the exact same pattern as GitHub OAuth. The implementation will support:

- ✅ GitLab.com (SaaS)
- ✅ Self-hosted GitLab instances
- ✅ Group-based role mapping
- ✅ OSS compatibility (no enterprise restrictions)

## Implementation Tasks

### Phase 1: Core Types and Constants

#### 1. GitLab Connector Types (`api/types/gitlab.go`)
```go
// GitlabConnector represents a GitLab OAuth2 connector
type GitlabConnector interface {
    Resource
    GetClientID() string
    GetClientSecret() string
    GetRedirectURL() string
    GetEndpointURL() string
    GetAPIEndpointURL() string
    GetGroupsToRoles() []GroupRolesMapping
    GetDisplay() string
    // ... additional methods
}

// GroupRolesMapping represents mapping between GitLab groups and Teleport roles
type GroupRolesMapping struct {
    Group string   `json:"group"`
    Roles []string `json:"roles"`
}
```

#### 2. Constants (`api/constants/constants.go`)
```go
// GitLab OAuth constants
const (
    GitlabAuthPath  = "oauth/authorize"
    GitlabTokenPath = "oauth/token"
    GitlabUserPath  = "api/v4/user"
    GitlabGroupsPath = "api/v4/groups"
)

// GitLab OAuth scopes
var GitlabScopes = []string{
    "read_user",  // Read user profile
    "read_api",   // Read user's groups
}
```

### Phase 2: Core Authentication Logic

#### 3. GitLab Auth Service (`lib/auth/gitlab.go`)
Key functions to implement:
- `CreateGitlabAuthRequest()` - Initialize OAuth flow
- `ValidateGitlabAuthCallback()` - Process OAuth callback
- `getGitlabUserAndGroups()` - Fetch user data from GitLab API
- `calculateGitlabUser()` - Map GitLab user to Teleport user
- `createGitlabUser()` - Create/update Teleport user

#### 4. GitLab API Client
```go
type gitlabAPIClient struct {
    token       string
    authServer  *Server
    apiEndpoint string
}

func (c *gitlabAPIClient) getUser() (*GitlabUserResponse, error)
func (c *gitlabAPIClient) getGroups() ([]GitlabGroupResponse, error)
```

### Phase 3: Web Integration

#### 5. Web Endpoints (`lib/web/apiserver.go`)
Add these endpoints in `bindDefaultEndpoints()`:
```go
// GitLab connector handlers
h.GET("/webapi/gitlab/login/web", h.WithRedirect(h.gitlabLoginWeb))
h.GET("/webapi/gitlab/callback", h.WithMetaRedirect(h.gitlabCallback))
h.POST("/webapi/gitlab/login/console", h.WithLimiter(h.gitlabLoginConsole))

// GitLab connector management
h.GET("/webapi/gitlab", h.WithAuth(h.getGitlabConnectorsHandle))
h.POST("/webapi/gitlab", h.WithAuth(h.createGitlabConnectorHandle))
h.GET("/webapi/gitlab/connector/:name", h.WithAuth(h.getGitlabConnectorHandle))
h.PUT("/webapi/gitlab/:name", h.WithAuth(h.updateGitlabConnectorHandle))
h.DELETE("/webapi/gitlab/:name", h.WithAuth(h.deleteGitlabConnector))
```

#### 6. Web Handler Functions
- `gitlabLoginWeb()` - Handle web login initiation
- `gitlabCallback()` - Handle OAuth callback
- `gitlabLoginConsole()` - Handle console login
- GitLab connector CRUD handlers

### Phase 4: Backend Services

#### 7. Services Layer (`lib/services/`)
- GitLab connector validation
- GitLab connector unmarshaling
- Backend storage interface methods

#### 8. Backend Storage
Update backend implementations to support GitLab connectors:
- `GetGitlabConnector()`
- `GetGitlabConnectors()`
- `CreateGitlabConnector()`
- `UpdateGitlabConnector()`
- `DeleteGitlabConnector()`

### Phase 5: Configuration and Validation

#### 9. Auth Preference Updates
Add GitLab as a supported authentication type:
```go
const (
    // ... existing types
    Gitlab = "gitlab"
)
```

#### 10. Configuration Validation
- Validate GitLab connector configuration
- Set reasonable defaults
- URL validation for self-hosted instances

### Phase 6: Testing

#### 11. Unit Tests
- Test GitLab OAuth flow
- Test API client functionality
- Test user/group mapping logic
- Test error handling

#### 12. Integration Tests
- End-to-end OAuth flow testing
- Web UI integration testing
- Configuration validation testing

## Configuration Examples

### Basic GitLab.com Configuration
```yaml
auth_service:
  authentication:
    type: gitlab
    gitlab:
      client_id: "your-gitlab-app-id"
      client_secret: "your-gitlab-app-secret"
      redirect_url: "https://teleport.example.com/v1/webapi/gitlab/callback"
      groups_to_roles:
        - group: "admin"
          roles: ["editor", "access"]
        - group: "developers"
          roles: ["access"]
```

### Self-hosted GitLab Configuration
```yaml
auth_service:
  authentication:
    type: gitlab
    gitlab:
      client_id: "your-gitlab-app-id"
      client_secret: "your-gitlab-app-secret"
      redirect_url: "https://teleport.example.com/v1/webapi/gitlab/callback"
      endpoint_url: "https://gitlab.company.com"
      api_endpoint_url: "https://gitlab.company.com/api/v4"
      groups_to_roles:
        - group: "platform-team"
          roles: ["editor"]
        - group: "developers"
          roles: ["access"]
```

## Key Files to Create/Modify

### New Files to Create:
- `api/types/gitlab.go` - GitLab connector types and interfaces
- `lib/auth/gitlab.go` - Core GitLab authentication logic
- `lib/auth/gitlab_test.go` - Unit tests for GitLab auth

### Files to Modify:
- `api/constants/constants.go` - Add GitLab constants
- `lib/auth/auth.go` - Add GitLab methods to Server
- `lib/auth/auth_with_roles.go` - Add GitLab RBAC methods
- `lib/web/apiserver.go` - Add GitLab endpoints and handlers
- `lib/web/resources.go` - Add GitLab connector CRUD handlers
- `lib/services/` - Add GitLab connector services
- Backend implementations - Add GitLab connector storage

## GitLab OAuth Setup Instructions

### 1. Create GitLab Application
1. Go to GitLab → User Settings → Applications
2. Add new application with:
   - Name: "Teleport SSO"
   - Redirect URI: `https://teleport.example.com/v1/webapi/gitlab/callback`
   - Scopes: `read_user`, `read_api`

### 2. Configure Teleport
Add GitLab connector configuration to `/etc/teleport.yaml`

### 3. Set Default Authentication
```bash
tctl auth export --type auth_preference > auth_pref.yaml
# Edit auth_pref.yaml to set type: gitlab
tctl create auth_pref.yaml
```

## Implementation Order

1. **Start with types and constants** (gitlab-types, gitlab-constants)
2. **Core authentication logic** (gitlab-auth-core, gitlab-api-client)
3. **Server integration** (gitlab-server-methods, gitlab-server-roles)
4. **Web endpoints** (gitlab-web-endpoints, gitlab-web-handlers)
5. **Backend services** (gitlab-services, gitlab-backend-storage)
6. **Testing and validation** (gitlab-unit-tests, gitlab-integration-tests)
7. **Documentation and examples** (gitlab-config-examples)

## Success Criteria

- [ ] Users can authenticate via GitLab OAuth
- [ ] Group-based role mapping works correctly
- [ ] Supports both GitLab.com and self-hosted instances
- [ ] Web UI integration works seamlessly
- [ ] Configuration validation prevents common errors
- [ ] Comprehensive test coverage
- [ ] Clear documentation and examples

## Notes

- Follow the exact same pattern as GitHub OAuth implementation
- No enterprise restrictions - fully OSS compatible
- Support for self-hosted GitLab instances
- Group-based role mapping (not org/teams like GitHub)
- Comprehensive error handling and user feedback 