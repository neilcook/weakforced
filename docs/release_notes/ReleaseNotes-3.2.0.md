# Release Notes for OX Abuse Shield 3.2.0

<!-- {% raw %} -->

## New Features
* Add the `replfwd` daemon for forwarding replication events between wforce clusters and other replication forwarders.
* Add Redis TLS support for persistent blacklist and whitelist connections, including CA, client certificate, peer verification, and server name configuration.
* Add `reloadGeoIP2DBs()` to reload GeoIP2 databases at runtime.
* Add configurable IPv4 and IPv6 prefix lengths for blacklist and whitelist IP entries via `setBlacklistV4Prefix()`, `setBlacklistV6Prefix()`, `setWhitelistV4Prefix()`, and `setWhitelistV6Prefix()`.
* Add prefix-aware Lua methods for IP/login and IP/JA3 blacklist and whitelist entries.
* Add `netmask` support to the blacklist and whitelist REST API add/delete commands. The `netmask` parameter is mutually exclusive with `ip`, `login`, and `ja3`.
* Add Lua helper functions and methods for working with `Netmask` and `ComboAddress` values, including `newNetmaskFromCA()` and `Netmask:toStringNetwork()`.

## Bug Fixes
* Fix JA3 blacklist entries not being reloaded from Redis on startup.
* Fix `getIPJA3Blacklist()` incorrectly calling `getIPLoginBlacklist()`.
* Fix the `expireEntrylog` log line.

## Improvements
* Add Ubuntu Noble, Ubuntu Jammy, and Ubuntu Resolute build targets.
* Update the regression test environment for Ubuntu Noble and Python 3.12 compatibility.
* Add `replfwd` documentation, OpenAPI documentation, packaging support, and CI coverage.
* Add missing command completion functions.

<!-- {% endraw %} -->
