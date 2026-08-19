<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Local platform bootstrap

Bootstrap is deliberately local and single-use. It creates the first user,
marks that user as a platform operator, creates their personal organization,
and grants owner access only inside that organization. Platform operation does
not imply access to another organization's telemetry.

Production configuration and the generated password file must be root-owned,
mode `0600`, regular files. Observatory creates the file exclusively and
refuses an existing path. The password is never a command argument, output
field, manifest value, log value, or persisted cleartext value.

```sh
sudo observatory admin bootstrap \
  --config /etc/gamertan-observatory/server.json \
  --username operator \
  --email operator@example.com \
  --display-name 'First Operator' \
  --generate-password-file /root/observatory-bootstrap-password
```

The command returns only the opaque user and personal-organization IDs plus
`password_change_required: true`. Read the file locally, sign in, and replace
the temporary credential. That session is restricted to password rotation,
logout, health, and immutable application-shell assets. A successful change
revokes every session, clears the browser cookie, and requires a fresh login.
Delete the generated file only after the replacement login succeeds.

## Recover local access

If an operator loses a credential, recover it only from the host. Observatory
does not expose a password-reset route, email flow, recovery token API, or
registration window:

```sh
sudo env CREDENTIALS_DIRECTORY=/run/credentials/gamertan-observatory.service \
  observatory admin user reset-password \
  --config /run/credentials/gamertan-observatory.service/server.json \
  --systemd-credential-config \
  --identifier speelman \
  --generate-password-file /root/observatory-password-recovery
```

The command creates the output file exclusively as a root-owned regular file
with mode `0600`. It then atomically installs that one-time credential, restores
the password-change requirement, revokes every session, and appends a generic
audit event without the credential or its path. If the database operation
fails, the generated file is removed. Read the file locally, complete the
server-rendered password-change form, and delete the file after the new login
succeeds. Never place the credential in shell arguments, chat, logs, manifests,
or deployment state.

There is no public first-user registration window. The bootstrap command is
single-use, local, and refuses a second platform user. If an operator already
has an appropriately generated password, `--password-file` remains available;
that explicitly supplied credential is treated as permanent and does not set
the forced-change flag. The two password flags are mutually exclusive.

If bootstrap fails after creating a generated credential, Observatory removes
the file after revalidating its exact path, type, owner, and mode. A process
crash between file creation and database bootstrap can leave a credential with
no account; inspect the control database and remove that exact file before a
reviewed retry. Never replace the path with a symlink or broaden its mode.

When the installed service loads its configuration and Web Push key through
systemd credentials, use that same confined runtime view rather than copying
or changing credential modes:

```sh
sudo env CREDENTIALS_DIRECTORY=/run/credentials/gamertan-observatory.service \
  observatory admin bootstrap \
  --config /run/credentials/gamertan-observatory.service/server.json \
  --systemd-credential-config \
  --username operator \
  --email operator@example.com \
  --display-name 'First Operator' \
  --generate-password-file /root/observatory-bootstrap-password
```

The systemd mode accepts only a direct child of the declared credential
directory, owned by root or the current service user, with mode `0400`, `0440`,
or `0600`. It is mutually exclusive with the local non-root development flag.
Every command that loads the server configuration—including user, invitation,
resource, enrollment, descriptor, retention, query, import, export, and
migration operations—accepts the same `--systemd-credential-config` boundary.
Operators do not need to copy a runtime credential or weaken its mode merely
to run an administrative command.

The browser login form carries an independent, short-lived, unpredictable
token in a Secure, HttpOnly, SameSite=Strict cookie and the rendered form.
Authenticated forms use separate purpose-bound tokens derived from the opaque
session. These tokens are the primary CSRF proof for ordinary server POSTs.
`Origin` and Fetch Metadata are independent contradiction checks: explicitly
cross-site requests and tokenless requests remain rejected, while missing or
opaque metadata from privacy tools cannot prevent a valid form submission.
Failures return a fresh server-rendered form with bounded guidance and never
echo the submitted identifier or password.

## Add a user through an invitation

Later users are provisioned locally. Each receives an automatically created
personal organization, but no access to anyone else's telemetry. Create a
private password file without placing the password in shell history, then run:

```sh
sudo observatory admin user create \
  --config /etc/gamertan-observatory/server.json \
  --username responder \
  --email responder@example.com \
  --display-name 'Incident Responder' \
  --password-file /etc/gamertan-observatory/responder-password
```

An owner of the destination organization creates an expiring, single-use
invitation. The owner must supply their opaque user and organization IDs:

```sh
sudo observatory admin invitation create \
  --config /etc/gamertan-observatory/server.json \
  --actor-user-id USER_ID \
  --organization-id ORGANIZATION_ID \
  --email responder@example.com \
  --lifetime 15m \
  --output-file /etc/gamertan-observatory/responder-invitation
```

The token is written only to the new mode-`0600` file. Existing paths,
symlinks, multiline values, and weak files fail closed; a database invitation
is cancelled automatically if its token file cannot be persisted. Command
output contains metadata, never the token. Transfer the file through a
separately protected channel and accept it locally:

```sh
sudo observatory admin invitation accept \
  --config /etc/gamertan-observatory/server.json \
  --user-id INVITED_USER_ID \
  --invitation-file /etc/gamertan-observatory/responder-invitation
```

Acceptance requires the provisioned user's exact normalized email address.
The token cannot be reused. Remove both password and invitation files after
the user confirms access. The preview intentionally has no public registration,
email-delivery protocol, or self-service invitation UI.

Bootstrap and later user provisioning each create a user, personal
organization, and access grant through separately checked storage operations.
Until that sequence becomes one control-database transaction, retain a
verified control-database backup before provisioning identities. If a command
reports a partial provisioning failure, stop and restore or inspect the
database rather than blindly retrying it.
