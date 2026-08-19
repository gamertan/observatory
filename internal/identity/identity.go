// SPDX-License-Identifier: AGPL-3.0-only

// Package identity binds Observatory's application policy to the storage-neutral
// Gamertan Web Foundations authentication, organization, and access packages.
package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authsqlite"
	"gamertan.com/web/organizations"
	_ "modernc.org/sqlite"
)

const (
	PlatformOperator   = "platform.operator"
	OrganizationOwner  = "organization.owner"
	OrganizationViewer = "organization.viewer"
	IncidentResponder  = "incident.responder"

	PermissionPlatformOperate        = "platform.operate"
	PermissionTelemetryQuery         = "telemetry.query"
	PermissionTelemetryReadSensitive = "telemetry.sensitive"
	PermissionSourcesManage          = "sources.manage"
	PermissionSchemaManage           = "schema.manage"
	PermissionDashboardsRead         = "dashboards.read"
	PermissionDashboardsManage       = "dashboards.manage"
	PermissionIncidentsRead          = "incidents.read"
	PermissionIncidentsManage        = "incidents.manage"
	PermissionOrganizationAudit      = "organization.audit.read"
	PermissionOrganizationManage     = "organization.manage"
)

var (
	ErrAlreadyBootstrapped = errors.New("identity: platform is already bootstrapped")
	ErrResourceNotFound    = errors.New("identity: resource scope not found")
)

type Services struct {
	Store         *authsqlite.Store
	Auth          *auth.Service
	Organizations *organizations.Service
	Access        *access.Service
	control       *sql.DB
	dataDir       string
}

func Open(dataDir string) (*Services, error) {
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return nil, errors.New("identity: data directory must be absolute and clean")
	}
	info, err := os.Lstat(dataDir)
	if err != nil {
		return nil, fmt.Errorf("identity: inspect data directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("identity: data directory must be a private non-symlink directory")
	}
	controlPath := filepath.Join(dataDir, "control.sqlite")
	store, err := authsqlite.Open(controlPath)
	if err != nil {
		return nil, err
	}
	authService, err := auth.New(store, auth.Options{})
	if err != nil {
		store.Close()
		return nil, err
	}
	organizationService, err := organizations.New(store, organizations.Options{})
	if err != nil {
		store.Close()
		return nil, err
	}
	accessService, err := access.New(store, AccessPolicy(), access.Options{})
	if err != nil {
		store.Close()
		return nil, err
	}
	control, err := sql.Open("sqlite", sqliteDSN(controlPath))
	if err != nil {
		store.Close()
		return nil, err
	}
	control.SetMaxOpenConns(1)
	services := &Services{Store: store, Auth: authService, Organizations: organizationService, Access: accessService, control: control, dataDir: dataDir}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = services.seed(ctx); err != nil {
		services.Close()
		return nil, err
	}
	return services, nil
}

func (services *Services) Close() error {
	var errs []error
	if services.control != nil {
		errs = append(errs, services.control.Close())
	}
	if services.Store != nil {
		errs = append(errs, services.Store.Close())
	}
	return errors.Join(errs...)
}

func PlatformPolicy() auth.PolicySeed {
	return auth.PolicySeed{
		Roles:           map[string]string{PlatformOperator: "Operate the Observatory service without implicit access to organization telemetry."},
		Permissions:     map[string]string{PermissionPlatformOperate: "Operate platform-level service and migration controls."},
		RolePermissions: map[string][]string{PlatformOperator: {PermissionPlatformOperate}},
	}
}

func AccessPolicy() access.Policy {
	permissions := map[string]string{
		PermissionTelemetryQuery:         "Query telemetry in an explicitly authorized resource scope.",
		PermissionTelemetryReadSensitive: "Read fields classified as sensitive.",
		PermissionSourcesManage:          "Enroll, rotate, and revoke ingestion sources.",
		PermissionSchemaManage:           "Review field descriptors and projection changes.",
		PermissionDashboardsRead:         "Read saved queries and dashboards.",
		PermissionDashboardsManage:       "Create and change saved queries and dashboards.",
		PermissionIncidentsRead:          "Read incidents for an authorized scope.",
		PermissionIncidentsManage:        "Acknowledge, silence, and resolve incidents.",
		PermissionOrganizationAudit:      "Read organization-visible security and access audit events.",
		PermissionOrganizationManage:     "Manage organization membership invitations and teams.",
	}
	return access.Policy{
		Roles: map[string]string{
			OrganizationOwner:  "Manage an organization and its Observatory resources.",
			OrganizationViewer: "Read ordinary telemetry, dashboards, and incidents.",
			IncidentResponder:  "Read telemetry and respond to incidents without managing sources or access.",
		},
		Permissions: permissions,
		Grants: map[string][]string{
			OrganizationOwner: {
				PermissionTelemetryQuery, PermissionTelemetryReadSensitive,
				PermissionSourcesManage, PermissionSchemaManage, PermissionDashboardsRead,
				PermissionDashboardsManage, PermissionIncidentsRead,
				PermissionIncidentsManage, PermissionOrganizationAudit,
				PermissionOrganizationManage,
			},
			OrganizationViewer: {PermissionTelemetryQuery, PermissionDashboardsRead, PermissionIncidentsRead},
			IncidentResponder:  {PermissionTelemetryQuery, PermissionDashboardsRead, PermissionIncidentsRead, PermissionIncidentsManage},
		},
	}
}

func (services *Services) CancelUnusedInvitation(ctx context.Context, digest [32]byte) error {
	result, err := services.control.ExecContext(ctx, `DELETE FROM gwf_organization_invitations WHERE token_hash=? AND used_at IS NULL`, digest[:])
	if err != nil {
		return errors.New("identity: cancel invitation")
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("identity: unused invitation was not found")
	}
	return nil
}

func (services *Services) seed(ctx context.Context) error {
	if err := services.Store.SeedPolicy(ctx, PlatformPolicy()); err != nil {
		return fmt.Errorf("identity: seed platform policy: %w", err)
	}
	if err := services.Access.Seed(ctx); err != nil {
		return fmt.Errorf("identity: seed organization access policy: %w", err)
	}
	return nil
}

func (services *Services) ValidateResourceScope(ctx context.Context, scope access.Scope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	queryText := `SELECT COUNT(*) FROM gwf_organizations WHERE id=?`
	arguments := []any{scope.OrganizationID}
	switch {
	case scope.ServiceID != "":
		queryText = `SELECT COUNT(*) FROM gwf_application_services WHERE id=? AND environment_id=? AND project_id=? AND organization_id=?`
		arguments = []any{scope.ServiceID, scope.EnvironmentID, scope.ProjectID, scope.OrganizationID}
	case scope.EnvironmentID != "":
		queryText = `SELECT COUNT(*) FROM gwf_environments WHERE id=? AND project_id=? AND organization_id=?`
		arguments = []any{scope.EnvironmentID, scope.ProjectID, scope.OrganizationID}
	case scope.ProjectID != "":
		queryText = `SELECT COUNT(*) FROM gwf_projects WHERE id=? AND organization_id=?`
		arguments = []any{scope.ProjectID, scope.OrganizationID}
	}
	var count int
	if err := services.control.QueryRowContext(ctx, queryText, arguments...).Scan(&count); err != nil {
		return fmt.Errorf("identity: validate resource scope: %w", err)
	}
	if count != 1 {
		return ErrResourceNotFound
	}
	return nil
}

// OrganizationsForUser returns only active organizations in which the user
// has a direct membership. Access grants remain the independent authority for
// every operation performed after selection.
func (services *Services) OrganizationsForUser(ctx context.Context, userID string) ([]organizations.Organization, error) {
	memberships, err := services.Organizations.Memberships(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("identity: list organization memberships: %w", err)
	}
	result := make([]organizations.Organization, 0, len(memberships))
	for _, membership := range memberships {
		if membership.Status != "active" {
			continue
		}
		var organization organizations.Organization
		var personal int
		var createdAt int64
		err = services.control.QueryRowContext(ctx, `SELECT id,slug,name,personal,created_at FROM gwf_organizations WHERE id=?`, membership.OrganizationID).Scan(&organization.ID, &organization.Slug, &organization.Name, &personal, &createdAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrResourceNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("identity: read organization: %w", err)
		}
		organization.Personal = personal == 1
		organization.CreatedAt = time.Unix(createdAt, 0).UTC()
		result = append(result, organization)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].ID < result[j].ID
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

type BootstrapInput struct {
	Username, Email, DisplayName, Password string
	RequirePasswordChange                  bool
}

type BootstrapResult struct {
	User         auth.User
	Organization organizations.Organization
	Binding      access.Binding
}

type UserProvisionResult struct {
	User         auth.User
	Organization organizations.Organization
	Binding      access.Binding
}

// ProvisionUser creates an active local user and the personal organization
// that owns their private work. Shared organization access still requires a
// separately authorized, expiring invitation.
func (services *Services) ProvisionUser(ctx context.Context, input auth.CreateUser) (UserProvisionResult, error) {
	user, err := services.Auth.CreateUser(ctx, input)
	if err != nil {
		return UserProvisionResult{}, fmt.Errorf("identity: create user: %w", err)
	}
	organization, err := services.Organizations.CreatePersonalOrganization(ctx, user.ID, user.DisplayName)
	if err != nil {
		return UserProvisionResult{}, fmt.Errorf("identity: create personal organization: %w", err)
	}
	binding, err := services.Access.Grant(ctx, access.Grant{
		SubjectKind: access.User, SubjectID: user.ID, Role: OrganizationOwner,
		Scope: access.Scope{OrganizationID: organization.ID}, GrantedBy: user.ID,
	})
	if err != nil {
		return UserProvisionResult{}, fmt.Errorf("identity: grant personal organization ownership: %w", err)
	}
	return UserProvisionResult{User: user, Organization: organization, Binding: binding}, nil
}

func (services *Services) Bootstrap(ctx context.Context, input BootstrapInput) (BootstrapResult, error) {
	lock, err := openBootstrapLock(filepath.Join(services.dataDir, ".bootstrap.lock"))
	if err != nil {
		return BootstrapResult{}, err
	}
	defer lock.Close()
	var users int
	if err = services.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_users`).Scan(&users); err != nil {
		return BootstrapResult{}, fmt.Errorf("identity: inspect bootstrap state: %w", err)
	}
	if users != 0 {
		return BootstrapResult{}, ErrAlreadyBootstrapped
	}
	provisioned, err := services.ProvisionUser(ctx, auth.CreateUser{
		Username: input.Username, Email: input.Email,
		DisplayName: input.DisplayName, Password: input.Password,
		RequirePasswordChange: input.RequirePasswordChange,
	})
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("identity: create first operator: %w", err)
	}
	now := time.Now().UTC()
	if err = services.Store.GrantRole(ctx, provisioned.User.ID, PlatformOperator, now); err != nil {
		return BootstrapResult{}, fmt.Errorf("identity: grant platform operator: %w", err)
	}
	return BootstrapResult{User: provisioned.User, Organization: provisioned.Organization, Binding: provisioned.Binding}, nil
}

func openBootstrapLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("identity: open bootstrap lock: %w", err)
	}
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("identity: another bootstrap operation is active")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("identity: bootstrap lock must be a private regular file")
	}
	return file, nil
}

func sqliteDSN(path string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"}).String()
}

func ReadSecret(path string, requireRoot bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("identity: secret path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("identity: inspect secret file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return "", errors.New("identity: secret must be a regular non-symlink file with mode 0600")
	}
	if requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", errors.New("identity: secret must be owned by root")
		}
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("identity: read secret file: %w", err)
	}
	secret := strings.TrimSuffix(string(value), "\n")
	secret = strings.TrimSuffix(secret, "\r")
	if secret == "" || strings.ContainsAny(secret, "\x00\r\n") {
		return "", errors.New("identity: secret file must contain one non-empty line")
	}
	return secret, nil
}

func WriteSecret(path, secret string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || secret == "" || len(secret) > 1024 || strings.ContainsAny(secret, "\x00\r\n") {
		return errors.New("identity: secret output is invalid")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("identity: secret output directory must be an existing non-symlink directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("identity: create secret output: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		_, err = io.WriteString(file, secret+"\n")
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("identity: persist secret output")
	}
	directory, err := os.Open(parent)
	if err != nil {
		return errors.New("identity: open secret output directory")
	}
	if err = directory.Sync(); err != nil {
		directory.Close()
		return errors.New("identity: persist secret output directory")
	}
	if err = directory.Close(); err != nil {
		return errors.New("identity: close secret output directory")
	}
	remove = false
	return nil
}

// RemoveSecret removes only an exact private regular secret file and syncs its
// parent directory. It is used to clean up a generated bootstrap credential
// when bootstrap cannot commit an operator.
func RemoveSecret(path string, requireRoot bool) error {
	if _, err := ReadSecret(path, requireRoot); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("identity: remove secret file: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("identity: open secret output directory")
	}
	if err = directory.Sync(); err != nil {
		directory.Close()
		return errors.New("identity: persist secret output directory")
	}
	if err = directory.Close(); err != nil {
		return errors.New("identity: close secret output directory")
	}
	return nil
}
