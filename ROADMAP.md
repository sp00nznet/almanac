# Roadmap

## Next, roughly in order

1. **Alerting.** Email or a webhook for the certificate sweep and for lineage hosts that
   stop reporting. For now it's an exit code.
2. **More importers.** The generic `items` model fits other platforms' exports. Each one
   needs a column map, not a schema change.
3. **More certificate sources.** AD CS issued-certificate queries, and local certificate
   stores over WinRM.
4. **Domain expiry via RDAP.** Replaces hand-entered `expires_on` dates, the same way the
   sweep replaced certificate dates.
5. **Per-org vault keys**, so a departed customer's secrets can be made unreadable. For now
   there's one key.

## Known gaps

- There's no document *body* editor: items are made of fields.
- Passwords shorter than 8 characters pasted into notes aren't caught.
- No CSRF tokens. State-changing requests are POST-only and checked against `Origin`.
- The UI is functional, not polished.

## Out of scope

- A hosted/SaaS version. almanac is something you run.
- Remote control, ticketing, PSA features. It documents; other tools act.
