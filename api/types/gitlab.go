/*
Copyright 2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

import (
	"context"
	"log/slog"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/utils"
)

const (
	GitlabURL    = "https://gitlab.com"
	GitlabAPIURL = "https://gitlab.com/api/v4"
)

// GitlabConnector defines an interface for a GitLab OAuth2 connector
type GitlabConnector interface {
	// ResourceWithSecrets is a common interface for all resources
	ResourceWithSecrets
	ResourceWithOrigin
	// SetMetadata sets object metadata
	SetMetadata(meta Metadata)
	// GetClientID returns the connector client ID
	GetClientID() string
	// SetClientID sets the connector client ID
	SetClientID(string)
	// GetClientSecret returns the connector client secret
	GetClientSecret() string
	// SetClientSecret sets the connector client secret
	SetClientSecret(string)
	// GetRedirectURL returns the connector redirect URL
	GetRedirectURL() string
	// SetRedirectURL sets the connector redirect URL
	SetRedirectURL(string)
	// GetGroupsToRoles returns the mapping of GitLab groups to allowed roles
	GetGroupsToRoles() []GroupRolesMapping
	// SetGroupsToRoles sets the mapping of GitLab groups to allowed roles
	SetGroupsToRoles([]GroupRolesMapping)
	// MapClaims returns the list of allowed roles based on the retrieved claims
	// returns list of roles and kubernetes groups
	MapClaims(GitlabClaims) (roles []string, kubeGroups []string, kubeUsers []string)
	// GetDisplay returns the connector display name
	GetDisplay() string
	// SetDisplay sets the connector display name
	SetDisplay(string)
	// GetEndpointURL returns the endpoint URL
	GetEndpointURL() string
	// SetEndpointURL sets the endpoint URL
	SetEndpointURL(string)
	// GetAPIEndpointURL returns the API endpoint URL
	GetAPIEndpointURL() string
	// SetAPIEndpointURL sets the API endpoint URL
	SetAPIEndpointURL(string)
	// GetClientRedirectSettings returns the client redirect settings.
	GetClientRedirectSettings() *SSOClientRedirectSettings
}

// NewGitlabConnector creates a new GitLab connector from name and spec
func NewGitlabConnector(name string, spec GitlabConnectorSpecV3) (GitlabConnector, error) {
	c := &GitlabConnectorV3{
		Metadata: Metadata{
			Name: name,
		},
		Spec: spec,
	}
	if err := c.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return c, nil
}

// GetVersion returns resource version
func (c *GitlabConnectorV3) GetVersion() string {
	return c.Version
}

// GetKind returns resource kind
func (c *GitlabConnectorV3) GetKind() string {
	return c.Kind
}

// GetSubKind returns resource sub kind
func (c *GitlabConnectorV3) GetSubKind() string {
	return c.SubKind
}

// SetSubKind sets resource subkind
func (c *GitlabConnectorV3) SetSubKind(s string) {
	c.SubKind = s
}

// GetRevision returns the revision
func (c *GitlabConnectorV3) GetRevision() string {
	return c.Metadata.GetRevision()
}

// SetRevision sets the revision
func (c *GitlabConnectorV3) SetRevision(rev string) {
	c.Metadata.SetRevision(rev)
}

// GetName returns the name of the connector
func (c *GitlabConnectorV3) GetName() string {
	return c.Metadata.GetName()
}

// SetName sets the connector name
func (c *GitlabConnectorV3) SetName(name string) {
	c.Metadata.SetName(name)
}

// Expiry returns the connector expiration time
func (c *GitlabConnectorV3) Expiry() time.Time {
	return c.Metadata.Expiry()
}

// SetExpiry sets the connector expiration time
func (c *GitlabConnectorV3) SetExpiry(expires time.Time) {
	c.Metadata.SetExpiry(expires)
}

// SetMetadata sets connector metadata
func (c *GitlabConnectorV3) SetMetadata(meta Metadata) {
	c.Metadata = meta
}

// GetMetadata returns the connector metadata
func (c *GitlabConnectorV3) GetMetadata() Metadata {
	return c.Metadata
}

// Origin returns the origin value of the resource.
func (c *GitlabConnectorV3) Origin() string {
	return c.Metadata.Origin()
}

// SetOrigin sets the origin value of the resource.
func (c *GitlabConnectorV3) SetOrigin(origin string) {
	c.Metadata.SetOrigin(origin)
}

// WithoutSecrets returns an instance of resource without secrets.
func (c *GitlabConnectorV3) WithoutSecrets() Resource {
	if c.GetClientSecret() == "" {
		return c
	}
	c2 := *c
	c2.SetClientSecret("")
	return &c2
}

// setStaticFields sets static resource header and metadata fields.
func (c *GitlabConnectorV3) setStaticFields() {
	c.Kind = KindGitlabConnector
	c.Version = V3
}

// CheckAndSetDefaults verifies the connector is valid and sets some defaults
func (c *GitlabConnectorV3) CheckAndSetDefaults() error {
	c.setStaticFields()
	if err := c.Metadata.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}

	// make sure group mappings are valid
	for i, v := range c.Spec.GroupsToRoles {
		if v.Group == "" {
			return trace.BadParameter("groups_to_roles mapping #%v is invalid, group is empty.", i+1)
		}
	}

	if len(c.Spec.GroupsToRoles) == 0 {
		return trace.BadParameter("groups_to_roles mapping is invalid, no mappings defined.")
	}

	// Set default endpoint URLs if not provided
	if c.Spec.EndpointURL == "" {
		c.Spec.EndpointURL = GitlabURL
	}
	if c.Spec.APIEndpointURL == "" {
		c.Spec.APIEndpointURL = GitlabAPIURL
	}

	return nil
}

// GetClientID returns the connector client ID
func (c *GitlabConnectorV3) GetClientID() string {
	return c.Spec.ClientID
}

// SetClientID sets the connector client ID
func (c *GitlabConnectorV3) SetClientID(id string) {
	c.Spec.ClientID = id
}

// GetClientSecret returns the connector client secret
func (c *GitlabConnectorV3) GetClientSecret() string {
	return c.Spec.ClientSecret
}

// SetClientSecret sets the connector client secret
func (c *GitlabConnectorV3) SetClientSecret(secret string) {
	c.Spec.ClientSecret = secret
}

// GetRedirectURL returns the connector redirect URL
func (c *GitlabConnectorV3) GetRedirectURL() string {
	return c.Spec.RedirectURL
}

// SetRedirectURL sets the connector redirect URL
func (c *GitlabConnectorV3) SetRedirectURL(redirectURL string) {
	c.Spec.RedirectURL = redirectURL
}

// GetGroupsToRoles returns the mapping of GitLab groups to allowed roles
func (c *GitlabConnectorV3) GetGroupsToRoles() []GroupRolesMapping {
	return c.Spec.GroupsToRoles
}

// SetGroupsToRoles sets the mapping of GitLab groups to allowed roles
func (c *GitlabConnectorV3) SetGroupsToRoles(m []GroupRolesMapping) {
	c.Spec.GroupsToRoles = m
}

// GetDisplay returns the connector display name
func (c *GitlabConnectorV3) GetDisplay() string {
	return c.Spec.Display
}

// SetDisplay sets the connector display name
func (c *GitlabConnectorV3) SetDisplay(display string) {
	c.Spec.Display = display
}

// GetEndpointURL returns the endpoint URL
func (c *GitlabConnectorV3) GetEndpointURL() string {
	return c.Spec.EndpointURL
}

// SetEndpointURL sets the endpoint URL
func (c *GitlabConnectorV3) SetEndpointURL(url string) {
	c.Spec.EndpointURL = url
}

// GetAPIEndpointURL returns the API endpoint URL
func (c *GitlabConnectorV3) GetAPIEndpointURL() string {
	return c.Spec.APIEndpointURL
}

// SetAPIEndpointURL sets the API endpoint URL
func (c *GitlabConnectorV3) SetAPIEndpointURL(url string) {
	c.Spec.APIEndpointURL = url
}

// GetClientRedirectSettings returns the client redirect settings.
func (c *GitlabConnectorV3) GetClientRedirectSettings() *SSOClientRedirectSettings {
	if c == nil {
		return nil
	}
	return c.Spec.ClientRedirectSettings
}

// MapClaims returns a list of roles based on the provided claims,
// returns a list of roles and list of kubernetes groups
func (c *GitlabConnectorV3) MapClaims(claims GitlabClaims) ([]string, []string, []string) {
	var roles, kubeGroups, kubeUsers []string
	for _, mapping := range c.GetGroupsToRoles() {
		// Check if the user belongs to this group
		for _, userGroup := range claims.Groups {
			if userGroup == mapping.Group {
				roles = append(roles, mapping.Roles...)
				break
			}
		}
	}
	return utils.Deduplicate(roles), utils.Deduplicate(kubeGroups), utils.Deduplicate(kubeUsers)
}

// SetExpiry sets expiry time for the object
func (r *GitlabAuthRequest) SetExpiry(expires time.Time) {
	r.Expires = &expires
}

// Expiry returns object expiry setting.
func (r *GitlabAuthRequest) Expiry() time.Time {
	if r.Expires == nil {
		return time.Time{}
	}
	return *r.Expires
}

// Check makes sure the request is valid
func (r *GitlabAuthRequest) Check() error {
	authenticatedUserFlow := r.AuthenticatedUser != ""
	regularLoginFlow := !r.SSOTestFlow && !authenticatedUserFlow

	switch {
	case r.ConnectorID == "":
		return trace.BadParameter("missing ConnectorID")
	case r.StateToken == "":
		return trace.BadParameter("missing StateToken")
	// we could collapse these two checks into one, but the error message would become ambiguous.
	case r.SSOTestFlow && r.ConnectorSpec == nil:
		return trace.BadParameter("ConnectorSpec cannot be nil when SSOTestFlow is true")
	case authenticatedUserFlow && r.ConnectorSpec == nil:
		return trace.BadParameter("ConnectorSpec cannot be nil for authenticated user")
	case regularLoginFlow && r.ConnectorSpec != nil:
		return trace.BadParameter("ConnectorSpec must be nil")
	case len(r.PublicKey) != 0 && len(r.SshPublicKey) != 0:
		return trace.BadParameter("illegal to set both PublicKey and SshPublicKey")
	case len(r.PublicKey) != 0 && len(r.TlsPublicKey) != 0:
		return trace.BadParameter("illegal to set both PublicKey and TlsPublicKey")
	case r.AttestationStatement != nil && r.SshAttestationStatement != nil:
		return trace.BadParameter("illegal to set both AttestationStatement and SshAttestationStatement")
	case r.AttestationStatement != nil && r.TlsAttestationStatement != nil:
		return trace.BadParameter("illegal to set both AttestationStatement and TlsAttestationStatement")
	}
	sshPubKey := r.PublicKey
	if len(sshPubKey) == 0 {
		sshPubKey = r.SshPublicKey
	}
	if len(sshPubKey) > 0 {
		_, _, _, _, err := ssh.ParseAuthorizedKey(sshPubKey)
		if err != nil {
			return trace.BadParameter("bad SSH public key: %v", err)
		}
	}
	if len(r.PublicKey)+len(r.SshPublicKey)+len(r.TlsPublicKey) > 0 &&
		(r.CertTTL > defaults.MaxCertDuration || r.CertTTL < defaults.MinCertDuration) {
		return trace.BadParameter("wrong CertTTL")
	}
	return nil
}

// GroupRolesMapping represents mapping between GitLab groups and Teleport roles
type GroupRolesMapping struct {
	// Group is the GitLab group name
	Group string `json:"group"`
	// Roles is the list of Teleport roles to map to
	Roles []string `json:"roles"`
}

// GitlabClaims represents GitLab user claims
type GitlabClaims struct {
	// Username is the GitLab username
	Username string `json:"username"`
	// Groups is the list of GitLab groups the user belongs to
	Groups []string `json:"groups"`
	// UserID is the GitLab user ID
	UserID string `json:"user_id"`
	// Email is the user's email address
	Email string `json:"email"`
	// Name is the user's full name
	Name string `json:"name"`
}

// ValidateGitLabGroupName validates GitLab group name
func ValidateGitLabGroupName(name string) error {
	if name == "" {
		return trace.BadParameter("GitLab group name cannot be empty")
	}
	if len(name) > 255 {
		return trace.BadParameter("GitLab group name cannot exceed 255 characters")
	}
	return nil
} 