# App Source Map

- `App/PigeonApp.swift` — app lifecycle, unlock flow, and scene handling.
- `Core/Identity/` — identity key lifecycle and safety-number derivation.
- `Core/Contacts/ContactCard.swift` — QR payload format, signed identity bundle,
  display name, and signed relay endpoints.
- `Core/Session/` — session manager and messaging pipeline.
- `Core/Transport/PeerTransport.swift` — dual-role CoreBluetooth transport.
- `Core/Transport/RelayTransport.swift` — relay WebSocket transport.
- `Core/Transport/RelaySettings.swift` — user relay configuration.
- `Core/Mesh/MeshService.swift` — mesh envelope handling over a pluggable
  transport.
- `Core/Storage/` — encrypted local persistence.
- `Features/Home/` — chat list, menu, and relay settings UI.
- `Features/Contacts/` — QR display and scan/paste contact import.
- `Features/Chat/` — conversation UI.
