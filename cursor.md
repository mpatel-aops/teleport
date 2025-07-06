# Teleport GitLab OAuth Implementation Project

## Project Overview
Adding GitLab OAuth authentication support to Teleport OSS (Open Source). This implementation follows the exact same pattern as the existing GitHub OAuth connector but adapts it for GitLab's API and group-based authentication model.

## Current Status: Phase 1 Complete ✅
- **GitLab Connector Types**: Complete (`api/types/gitlab.go`)
- **Constants**: Complete (`api/constants/constants.go`) 
- **Next Phase**: Core authentication logic (`lib/auth/gitlab.go`)

## Key Implementation Details

### Architecture Pattern
- Following **GitHub OAuth pattern exactly** - same interfaces, same flow
- GitLab **groups** replace GitHub **organizations/teams** concept
- Supports both **GitLab.com** and **self-hosted GitLab instances**
- **OSS compatible** - no enterprise restrictions

### GitLab OAuth Flow
```
User → /webapi/gitlab/login/web → GitLab OAuth → /webapi/gitlab/callback → User authenticated
```

### Key Files Structure
```
api/types/gitlab.go              ✅ GitLab connector types & interfaces
api/constants/constants.go       ✅ Added Gitlab = "gitlab" constant  
lib/auth/gitlab.go              ⏳ NEXT: Core auth logic (like github.go)
lib/web/apiserver.go            ⏳ Web endpoints (/webapi/gitlab/*)
api/proto/.../types.proto       ⏳ Proto definitions needed
```

## Implementation Guidelines

### 1. Follow GitHub Pattern Exactly
- Copy `lib/auth/github.go` structure for `lib/auth/gitlab.go`
- Same method signatures: `CreateGitlabAuthRequest()`, `ValidateGitlabAuthCallback()`
- Same web endpoints pattern: `/webapi/gitlab/login/web`, `/webapi/gitlab/callback`

### 2. Key Differences from GitHub
```go
// GitHub uses orgs/teams
TeamsToRoles []TeamRolesMapping

// GitLab uses groups  
GroupsToRoles []GroupRolesMapping
```

### 3. GitLab API Integration
- **Auth URL**: `{endpoint}/oauth/authorize`
- **Token URL**: `{endpoint}/oauth/token`  
- **User API**: `{endpoint}/api/v4/user`
- **Groups API**: `{endpoint}/api/v4/groups`
- **Scopes**: `["read_user", "read_api"]`

### 4. Configuration Example
```yaml
auth_service:
  authentication:
    type: gitlab
    gitlab:
      client_id: "app-id"
      client_secret: "app-secret"
      redirect_url: "https://teleport.example.com/v1/webapi/gitlab/callback"
      endpoint_url: "https://gitlab.company.com"  # For self-hosted
      groups_to_roles:
        - group: "admin"
          roles: ["editor", "access"]
```

## Progress Tracking

### ✅ Completed (Phase 1)
- `gitlab-types`: GitLab connector types and interfaces
- `gitlab-constants`: Authentication type constant

### ⏳ Next Steps (Phase 2)  
1. **Add Proto Definitions** - `GitlabConnectorV3`, `GitlabConnectorSpecV3` in proto files
2. **Core Auth Logic** - Implement `lib/auth/gitlab.go` (copy/adapt `github.go`)
3. **Server Methods** - Add GitLab methods to `lib/auth/auth.go`

### 📋 Full Task List
See `GITLAB_OAUTH_IMPLEMENTATION.md` for complete implementation plan with 20 detailed tasks.

## Important Files to Reference

### For Implementation Patterns
- `lib/auth/github.go` - **Primary reference** for auth logic
- `lib/web/apiserver.go` - GitHub web endpoints (lines ~960-965)
- `api/types/github.go` - Connector interface patterns

### For Progress Tracking  
- `GITLAB_OAUTH_IMPLEMENTATION.md` - Complete implementation plan
- `GITLAB_OAUTH_PROGRESS.md` - Current session progress
- **TODO list** - Active task tracking (use `todo_write` tool)

## Key Implementation Notes

### 1. Proto Files Required
Missing proto definitions needed in `api/proto/teleport/legacy/types/types.proto`:
```protobuf
message GitlabConnectorV3 { ... }
message GitlabConnectorSpecV3 { ... }  
```

### 2. Error Handling
Follow same error patterns as GitHub - user-friendly messages, proper trace wrapping.

### 3. Testing Strategy  
- Unit tests for auth logic
- Integration tests for OAuth flow
- Self-hosted GitLab testing

### 4. Security Considerations
- Same CSRF protection as GitHub
- Same client redirect validation
- Support for `ClientRedirectSettings`

## When Resuming Work

1. **Check TODO status**: Use `todo_write` tool to see current task status
2. **Review progress**: Check `GITLAB_OAUTH_PROGRESS.md` for latest updates  
3. **Start with proto**: Add missing proto definitions first
4. **Follow GitHub pattern**: Copy and adapt `lib/auth/github.go` structure

This project implements a complete GitLab OAuth connector for Teleport OSS, enabling GitLab-based authentication with group-to-role mapping. 