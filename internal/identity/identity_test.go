// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/organizations"
)

func TestBootstrapSeparatesPlatformAndOrganizationAccess(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	services, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer services.Close()
	result, err := services.Bootstrap(context.Background(), BootstrapInput{
		Username: "operator", Email: "operator@example.test",
		DisplayName: "First Operator", Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Organization.Personal || result.Binding.Role != OrganizationOwner {
		t.Fatalf("result=%+v", result)
	}
	token, principal, err := services.Auth.Authenticate(context.Background(), "operator", "correct horse battery staple", time.Hour)
	if err != nil || token == "" || !principal.Has(PermissionPlatformOperate) {
		t.Fatalf("platform session: token_present=%t principal=%+v err=%v", token != "", principal, err)
	}
	decision, err := services.Access.Authorize(context.Background(), result.User.ID, access.Scope{OrganizationID: result.Organization.ID}, PermissionTelemetryQuery)
	if err != nil || !decision.Allowed || decision.Role != OrganizationOwner {
		t.Fatalf("query decision=%+v err=%v", decision, err)
	}
	decision, err = services.Access.Authorize(context.Background(), result.User.ID, access.Scope{OrganizationID: result.Organization.ID}, PermissionTelemetryReadSensitive)
	if err != nil || !decision.Allowed {
		t.Fatalf("sensitive decision=%+v err=%v", decision, err)
	}
	decision, err = services.Access.Authorize(context.Background(), result.User.ID, access.Scope{OrganizationID: result.Organization.ID}, PermissionSchemaManage)
	if err != nil || !decision.Allowed {
		t.Fatalf("schema decision=%+v err=%v", decision, err)
	}
	if _, err = services.Access.Authorize(context.Background(), result.User.ID, access.Scope{OrganizationID: result.Organization.ID}, PermissionPlatformOperate); err == nil {
		t.Fatal("platform permission entered organization access policy")
	}
	project, err := services.Organizations.CreateProject(context.Background(), organizations.CreateProject{OrganizationID: result.Organization.ID, Slug: "eql-helper", Name: "EQL Helper"})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := services.Organizations.CreateEnvironment(context.Background(), organizations.CreateEnvironment{OrganizationID: result.Organization.ID, ProjectID: project.ID, Slug: "production", Name: "Production"})
	if err != nil {
		t.Fatal(err)
	}
	application, err := services.Organizations.CreateApplicationService(context.Background(), organizations.CreateApplicationService{OrganizationID: result.Organization.ID, ProjectID: project.ID, EnvironmentID: environment.ID, Slug: "web", Name: "Web"})
	if err != nil {
		t.Fatal(err)
	}
	scope := access.Scope{OrganizationID: result.Organization.ID, ProjectID: project.ID, EnvironmentID: environment.ID, ServiceID: application.ID}
	if err = services.ValidateResourceScope(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	scope.ServiceID = "missing1"
	if err = services.ValidateResourceScope(context.Background(), scope); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("missing scope err=%v", err)
	}
}

func TestBootstrapIsSingleUse(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	services, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer services.Close()
	input := BootstrapInput{Username: "operator", Email: "operator@example.test", DisplayName: "First Operator", Password: "correct horse battery staple"}
	if _, err = services.Bootstrap(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err = services.Bootstrap(context.Background(), BootstrapInput{Username: "second", Email: "second@example.test", DisplayName: "Second Operator", Password: "correct horse battery staple"}); !errors.Is(err, ErrAlreadyBootstrapped) {
		t.Fatalf("second bootstrap err=%v", err)
	}
}

func TestBootstrapCanRequirePasswordChange(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	services, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer services.Close()
	result, err := services.Bootstrap(t.Context(), BootstrapInput{
		Username: "operator", Email: "operator@example.test", DisplayName: "First Operator",
		Password: "temporary correct horse battery staple", RequirePasswordChange: true,
	})
	if err != nil || !result.User.PasswordChangeRequired {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	_, principal, err := services.Auth.Authenticate(t.Context(), "operator", "temporary correct horse battery staple", time.Hour)
	if err != nil || !principal.User.PasswordChangeRequired {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
}

func TestRemoveSecretValidatesAndRemovesOnlyPrivateRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bootstrap-password")
	if err := WriteSecret(path, "temporary secret"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSecret(path, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed path err=%v", err)
	}
	unsafe := filepath.Join(root, "unsafe")
	if err := os.WriteFile(unsafe, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveSecret(unsafe, false); err == nil {
		t.Fatal("world-readable secret was removed")
	}
	if _, err := os.Stat(unsafe); err != nil {
		t.Fatalf("unsafe file changed: %v", err)
	}
}

func TestEvidenceRetentionPrunesOnlyExpiredAudit(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	services, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer services.Close()
	owner, err := services.Bootstrap(ctx, BootstrapInput{Username: "operator", Email: "operator@example.test", DisplayName: "First Operator", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 17, 5, 0, 0, 0, time.UTC)
	for _, event := range []struct {
		id      string
		created time.Time
	}{{"audit-old", now.Add(-401 * 24 * time.Hour)}, {"audit-current", now.Add(-399 * 24 * time.Hour)}} {
		if _, err = services.control.ExecContext(ctx, `INSERT INTO gwf_audit_events(id,actor_user_id,action,resource_type,resource_id,summary,created_at) VALUES(?,?,?,?,?,?,?)`, event.id, owner.User.ID, "session.test", "user", owner.User.ID, "Test event", event.created.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err = services.control.ExecContext(ctx, `INSERT INTO gwf_access_audit_events(id,organization_id,actor_user_id,action,resource_type,resource_id,summary,created_at) VALUES(?,?,?,?,?,?,?,?)`, "access-"+event.id, owner.Organization.ID, owner.User.ID, "access.test", "organization", owner.Organization.ID, "Test event", event.created.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	report, err := services.PruneEvidence(ctx, 400, now)
	if err != nil {
		t.Fatal(err)
	}
	if report.AuthenticationEvents != 1 || report.OrganizationEvents != 1 {
		t.Fatalf("report=%+v", report)
	}
	for _, table := range []string{"gwf_audit_events", "gwf_access_audit_events"} {
		var count int
		if err = services.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("table=%s count=%d err=%v", table, count, err)
		}
	}
}

func TestTeamsInvitationsRevocationAndBreakGlassRemainOrganizationScoped(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	services, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer services.Close()
	owner, err := services.Bootstrap(ctx, BootstrapInput{Username: "operator", Email: "operator@example.test", DisplayName: "First Operator", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := services.Auth.CreateUser(ctx, auth.CreateUser{Username: "responder", Email: "responder@example.test", DisplayName: "Incident Responder", Password: "another correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	rawInvitation, invitation, err := services.Organizations.Invite(ctx, owner.Organization.ID, member.Email, owner.User.ID, 15*time.Minute)
	if err != nil || rawInvitation == "" || invitation.OrganizationID != owner.Organization.ID {
		t.Fatalf("invitation=%+v token_present=%t err=%v", invitation, rawInvitation != "", err)
	}
	if err = services.Organizations.AcceptInvitation(ctx, rawInvitation, member.ID); err != nil {
		t.Fatal(err)
	}
	team, err := services.Organizations.CreateTeam(ctx, organizations.CreateTeam{OrganizationID: owner.Organization.ID, Slug: "responders", Name: "Incident Responders"})
	if err != nil {
		t.Fatal(err)
	}
	if err = services.Organizations.AddTeamMember(ctx, team.ID, member.ID); err != nil {
		t.Fatal(err)
	}
	binding, err := services.Access.Grant(ctx, access.Grant{SubjectKind: access.Team, SubjectID: team.ID, Role: IncidentResponder, Scope: access.Scope{OrganizationID: owner.Organization.ID}, GrantedBy: owner.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := services.Access.Authorize(ctx, member.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionIncidentsManage)
	if err != nil || !decision.Allowed || decision.Source != "role" || decision.Role != IncidentResponder {
		t.Fatalf("team decision=%+v err=%v", decision, err)
	}
	decision, err = services.Access.Authorize(ctx, owner.User.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionOrganizationManage)
	if err != nil || !decision.Allowed || decision.Role != OrganizationOwner {
		t.Fatalf("owner organization-management decision=%+v err=%v", decision, err)
	}
	decision, err = services.Access.Authorize(ctx, member.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionOrganizationManage)
	if err != nil || decision.Allowed {
		t.Fatalf("member organization-management decision=%+v err=%v", decision, err)
	}
	cancelToken, cancelInvitation, err := services.Organizations.Invite(ctx, owner.Organization.ID, "cancelled@example.test", owner.User.ID, 15*time.Minute)
	if err != nil || cancelToken == "" {
		t.Fatalf("cancel invitation=%+v token_present=%t err=%v", cancelInvitation, cancelToken != "", err)
	}
	if err = services.CancelUnusedInvitation(ctx, cancelInvitation.Digest); err != nil {
		t.Fatal(err)
	}
	if err = services.Organizations.AcceptInvitation(ctx, cancelToken, member.ID); err == nil {
		t.Fatal("cancelled invitation remained usable")
	}
	other, err := services.Organizations.CreatePersonalOrganization(ctx, member.ID, member.DisplayName)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = services.Access.Authorize(ctx, owner.User.ID, access.Scope{OrganizationID: other.ID}, PermissionTelemetryQuery)
	if err != nil || decision.Allowed {
		t.Fatalf("cross-organization decision=%+v err=%v", decision, err)
	}
	decision, err = services.Access.Authorize(ctx, member.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionTelemetryReadSensitive)
	if err != nil || decision.Allowed {
		t.Fatalf("unexpected sensitive decision=%+v err=%v", decision, err)
	}
	breakGlass, err := services.Access.ActivateBreakGlass(ctx, owner.Organization.ID, member.ID, PermissionTelemetryReadSensitive, "Investigate an active incident", "request-12345678", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = services.Access.Authorize(ctx, member.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionTelemetryReadSensitive)
	if err != nil || !decision.Allowed || decision.Source != "break_glass" {
		t.Fatalf("break-glass decision=%+v err=%v", decision, err)
	}
	audit, err := services.Access.Audit(ctx, owner.Organization.ID, 10)
	if err != nil || len(audit) != 1 || audit[0].Action != "break_glass.activate" || audit[0].ResourceID != owner.Organization.ID {
		t.Fatalf("audit=%+v err=%v", audit, err)
	}
	if _, err = services.control.ExecContext(ctx, `UPDATE gwf_break_glass SET expires_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), breakGlass.ID); err != nil {
		t.Fatal(err)
	}
	decision, err = services.Access.Authorize(ctx, member.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionTelemetryReadSensitive)
	if err != nil || decision.Allowed {
		t.Fatalf("expired break-glass decision=%+v err=%v", decision, err)
	}
	if err = services.Store.Revoke(ctx, binding.ID, owner.User.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	decision, err = services.Access.Authorize(ctx, member.ID, access.Scope{OrganizationID: owner.Organization.ID}, PermissionIncidentsManage)
	if err != nil || decision.Allowed {
		t.Fatalf("revoked team decision=%+v err=%v", decision, err)
	}
}

func TestReadSecretRejectsWeakFiles(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "password")
	if err := os.WriteFile(valid, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret, err := ReadSecret(valid, false)
	if err != nil || secret != "correct horse battery staple" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	weak := filepath.Join(dir, "weak")
	if err = os.WriteFile(weak, []byte("not private"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSecret(weak, false); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if err = os.Symlink(valid, link); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadSecret(link, false); err == nil {
			t.Fatal("symlinked secret accepted")
		}
	}
}

func TestWriteSecretIsPrivateExclusiveAndReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invitation")
	const secret = "single-use-invitation-token"
	if err := WriteSecret(path, secret); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%v err=%v", info, err)
	}
	got, err := ReadSecret(path, false)
	if err != nil || got != secret {
		t.Fatalf("secret=%q err=%v", got, err)
	}
	if err = WriteSecret(path, "replacement"); err == nil {
		t.Fatal("existing secret was overwritten")
	}
	if err = WriteSecret(filepath.Join(filepath.Dir(path), "multiline"), "first\nsecond"); err == nil {
		t.Fatal("multiline secret was accepted")
	}
	if runtime.GOOS != "windows" {
		linkedParent := filepath.Join(filepath.Dir(path), "linked-parent")
		if err = os.Symlink(filepath.Dir(path), linkedParent); err != nil {
			t.Fatal(err)
		}
		if err = WriteSecret(filepath.Join(linkedParent, "through-link"), "secret"); err == nil {
			t.Fatal("symlinked secret output directory was accepted")
		}
	}
}
