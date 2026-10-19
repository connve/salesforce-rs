# salesforce-rs

[![Test Suite](https://github.com/connve/salesforce-rs/actions/workflows/test.yml/badge.svg)](https://github.com/connve/salesforce-rs/actions/workflows/test.yml)
[![Security Audit](https://github.com/connve/salesforce-rs/actions/workflows/security.yml/badge.svg)](https://github.com/connve/salesforce-rs/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/connve/salesforce-rs)](https://github.com/connve/salesforce-rs/releases)
[![Crates.io](https://img.shields.io/crates/v/salesforce_core.svg)](https://crates.io/crates/salesforce_core)
[![Docs.rs](https://docs.rs/salesforce_core/badge.svg)](https://docs.rs/salesforce_core)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

Unofficial Rust SDK family for the Salesforce platform.

> Not affiliated with or endorsed by Salesforce, Inc.

## Crates

| Crate | Product cloud |
|-------|---------------|
| [`salesforce_core`](salesforce-core/README.md) | Salesforce Core (Sales, Service, Platform) — REST, Bulk 2.0, Pub/Sub, Tooling, SOAP |

## Project layout

```
salesforce-rs/
├── salesforce-core/           # User-facing crate for Core APIs
│   └── src/
│       ├── restapi/           # SObject CRUD, get deleted, SOQL query, search, composite
│       ├── bulkapi/           # Bulk 2.0 query and ingest
│       ├── toolingapi/        # Tooling API
│       ├── pubsubapi/         # Pub/Sub gRPC streaming
│       └── soapapi/           # SOAP-only operations
├── generated/
│   └── salesforce-core/       # Auto-generated API clients
│       ├── restapi/           # OpenAPI → progenitor
│       ├── bulkapi/
│       ├── toolingapi/
│       └── pubsubapi/         # Protobuf → tonic
└── examples/
    └── salesforce-core/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MPL-2.0
