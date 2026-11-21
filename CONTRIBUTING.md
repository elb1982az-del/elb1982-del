# Contributing

## Scope

Contributions must improve the controller, safety guardrails, documentation,
or test coverage. Do not add offensive payloads or bypass the authorization
checks in `engine/engine_cli.py`.

## Development

- Android: Kotlin + Jetpack Compose, SDK 35, JDK 17+.
- Engine bridge: Python 3.10+.

```bash
cd android && ./gradlew assembleDebug
cd ../engine && python3 -m pytest
```

## Rules

- Never commit `allowed_networks.json`, real IPs, credentials, or tokens.
- Keep the UI to the four-step flow: discover → fingerprint → check → sessions.
- Add tests for behavior changes in the bridge.
- Update `README.md` when behavior changes.
