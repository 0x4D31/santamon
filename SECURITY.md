# Security Considerations

## Permissions

Santa's spool directory (`/var/db/santa/spool`) requires root access:

- Run Santamon as root or with appropriate permissions
- State directory should be root-owned: `chown root:wheel /var/lib/santamon`
- Config files should be readable only by root: `chmod 600 /etc/santamon/*.yaml`

## Agent Resilience

Santamon isn't "unkillable" without kernel protections, but can be **resilient and noisy**:

### LaunchDaemon with Auto-Restart

- Installed as system LaunchDaemon with `KeepAlive`
- `launchd` automatically restarts if killed or crashed
- Default installation method (`make install`)

### Force Noisy Kills

- Ignore `SIGTERM`/`SIGINT` and log as tamper events
- Attackers must use `kill -9`, triggering immediate restart
- Restart creates visibility into tampering attempts

### Heartbeat Monitoring

- Agent sends periodic heartbeats to backend
- Missing heartbeats indicate agent failure or tampering
- Backend can alert ops team or trigger automatic remediation

### Self-Monitoring

- Use Santa file access rules to monitor Santamon binary and plist
- Alert on modifications to `/usr/local/bin/santamon` or `/Library/LaunchDaemons/com.santamon.plist`
- High-priority signals if core agent files are touched

**Goal:** Not perfect protection against determined root attackers, but resilience and visibility—if someone disables Santamon, it restarts quickly and you know about it.

## Known Limitations

- Process lineage is best-effort (1h cache, 50K entries, LRU eviction)
- Permanently failed signals remain in queue (no automatic purge)
