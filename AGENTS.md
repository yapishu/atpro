# `%atpro` development notes

- The source desk is `desk/`; use `zig build -Ddesk=<mounted-desk>` to assemble
  dependencies and copy it onto a mounted ship desk.
- Keep persisted schemas at `state-0` while this project is greenfield. Change
  `state-0` in place and nuke/revive agents during development; do not add
  migrations or compatibility shims.
- Never expose access JWTs, refresh JWTs, or app passwords through HTTP or
  scries. The browser receives only sanitized account metadata.
- Outbound URLs must remain constrained to the connected HTTPS PDS or the
  fixed public AppView origin. Do not accept arbitrary proxy URLs.
- Vere has no WebSocket client. Keep the native client HTTPS-only; add realtime
  through a separately authenticated webhook adapter rather than emulating a
  socket in Gall.
- Verify both `/app/atpro/hoon` and `/app/atpro-fileserver/hoon` on the target
  ship after Hoon changes.
