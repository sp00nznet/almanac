# Running almanac

## Serving

```
almanac-server almanac.db                                   # http://127.0.0.1:8771/
almanac-server almanac.db --host 0.0.0.0 --port 443 --cert fullchain.pem --key privkey.pem
```

- Off-loopback, it refuses to start without `--cert` and `--key`:
  `refusing to serve off-loopback without TLS: Basic auth would send passwords in the clear.`
  Putting it behind a reverse proxy on loopback also works, as long as the proxy speaks HTTPS.
- The vault passphrase comes from `ALMANAC_PASSPHRASE` or a prompt at startup. A wrong
  passphrase stops the server with `vault passphrase is wrong`, so a typo can't write
  secrets under a different key.
- With no admin yet it exits with `no admin yet: almanac-server almanac.db --add-user NAME`.

## Users

```
almanac-server almanac.db --add-user alice                              # admin (default role)
almanac-server almanac.db --add-user bob --role staff
almanac-server almanac.db --add-user acme-it --role member --org "Acme" --org "Acme East"
almanac-server almanac.db --add-user bob --role disabled                # offboard, keeps history
```

Admins can do the same from `/users` in the UI. An empty password at the prompt keeps the existing one.

## Backups

Everything, including attachments and the encrypted vault, is in the one `.db` file. Back it
up with SQLite's online backup so you never copy a half-written file:

```
sqlite3 almanac.db ".backup almanac-$(date +%F).db"
```

The backup is useless without the vault passphrase, so keep the passphrase somewhere else.
`almanac-export --secrets` produces a portable zip with every secret **decrypted**; treat it
like the passwords themselves.

## Scheduling the feeds

Neither feed runs as a daemon. Schedule them:

```
almanac-sync-lineage almanac.db /srv/lineage            # e.g. hourly
almanac-sweep-certs almanac.db --warn 30                # e.g. daily; exit 2 = something to act on
almanac-sweep-certs almanac.db --org "Acme" --sweep 192.0.2.0/24   # discovery on a subnet
```

`--sweep` and `--target` need `--org`: almanac never guesses which customer an unknown host
belongs to. The same rule applies to unmatched lineage hosts.

## Upgrading

`python -m pip install --upgrade .` from a fresh checkout. Schema changes so far are additive
and applied on open. Back up first anyway: this is alpha software.
