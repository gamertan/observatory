<!-- SPDX-License-Identifier: 0BSD -->

# Examples

Copy these files into your own deployment repository and adapt them. Production configuration belongs at `/etc/gamertan-observatory/`, must be root-owned mode `0600`, and should reference secrets stored in separate root-owned files. The example systemd unit uses `LoadCredential=` so the agent can consume runtime copies while remaining an unprivileged service.

The optional `web_push` block expects a private key created on the server with
`observatory admin web-push generate-key --output-file /etc/gamertan-observatory/web-push.json`.
Remove the block when browser notifications are not wanted. Never commit the
generated file.

`agent.json` demonstrates the privacy-minimized collection default. If an
application's privacy policy and operating purpose permit collection of client
addresses, queries, referrers, user agents, or anonymous session identifiers,
select those names explicitly in that source's `sensitive_fields` array. The
agent will not retain them merely because they exist in the producer log.

`Caddyfile.sensitive-access-log` is an intentionally richer edge-log example.
It still deletes request and response header maps, filters common credential
query keys, masks client addresses, and keeps the application request ID as a
correlation field. Its deny list cannot know an application's vocabulary:
review and extend it before use. Treat the resulting file as sensitive source
evidence with narrow read permissions and a documented retention period.
