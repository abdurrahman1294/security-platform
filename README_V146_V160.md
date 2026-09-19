# V146–V160 OSINT & Tooling Expansion

## OSINT
The operator now has a dedicated consent-first OSINT workspace covering infrastructure, public social-profile pivots, local image metadata/fingerprinting, public geodata research, web archives, public documents, timelines, and owner-controlled lost-device recovery.

It does **not** provide covert tracking, phone/IMEI/cell-tower surveillance, spyware, private-account access, credential harvesting, doxxing, or stalking.

### Lost devices
Use the official account-based recovery systems. Android devices can be located/secured/erased through Google Find Hub; Apple devices through Find My. The engine records the official recovery route and evidence checklist rather than attempting carrier-level or covert tracking.

### Image OSINT
Local images can be hashed and prepared for EXIF/GPS review and reverse-image-search workflows. Metadata is treated as evidence requiring corroboration.

### Social OSINT
The engine can generate public profile pivots and, when explicitly requested, perform simple public URL status checks. It does not log in, bypass controls, or collect private data.

## Tool catalog
V160 catalogs important open-source and commercial/trial-dependent security tools. Paid/trial products are only usable through legitimate registration/licensing and operator-supplied credentials. The catalog does not bypass licenses or automatically execute unapproved commercial tools.

## CLI additions
- `--osint-username USER`
- `--osint-image PATH` (repeatable)
- `--lost-device {android,apple,windows,other}`
- `--lost-device-id ID`
- `--tool-catalog`

## Testing
The full regression suite must remain green before packaging. New V146–V160 tests cover OSINT workspace creation, lost-device recovery routing, and tool catalog integrity.
