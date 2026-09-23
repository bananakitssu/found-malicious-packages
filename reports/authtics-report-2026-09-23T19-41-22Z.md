# Authtics PyPI Security Scan

Generated: 2026-09-23T19:41:22.123989+00:00

### Insecure Deserialization via pickle in Cache Backends
- **Advisory:** `AUTH-2026-00003`
- **CWE:** `CWE-502`
- **Package:** `fastapi-cachekit@0.2.1`
- **Severity:** `medium`
- **Confidence:** `0.8`
- **Review:** `PENDING`

The package uses the 'pickle' module for serializing and deserializing cached data across multiple backends (DynamoDB, Firestore, Memcached, MongoDB, Postgres, Redis).

**Evidence:**
- `fastapi_cachekit-0.2.1/fast_cache/backends/dynamodb.py` — Uses pickle.loads() to deserialize data retrieved from DynamoDB.
- `fastapi_cachekit-0.2.1/fast_cache/backends/google_firestore.py` — Uses pickle.loads() to deserialize data retrieved from Firestore.
- `fastapi_cachekit-0.2.1/fast_cache/backends/memcached.py` — Uses pickle.loads() to deserialize data retrieved from Memcached.
- `fastapi_cachekit-0.2.1/fast_cache/backends/mongodb.py` — Uses pickle.loads() to deserialize data retrieved from MongoDB.
- `fastapi_cachekit-0.2.1/fast_cache/backends/postgres.py` — Uses pickle.loads() to deserialize data retrieved from PostgreSQL.
- `fastapi_cachekit-0.2.1/fast_cache/backends/redis.py` — Uses pickle.loads() to deserialize data retrieved from Redis.

**Reviewer notes:**
- The use of the 'pickle' module for deserializing data from external cache stores is a well-known security risk. If an attacker can influence the contents of the cache (e.g., via a compromised Redis instance or other shared cache access), they could potentially achieve arbitrary code execution by injecting malicious pickled payloads.
- While this is a common pattern in Python caching libraries, it is inherently insecure if the cache store is not strictly protected and trusted.

### DRM and Obfuscation in Externum Package
- **Advisory:** `AUTH-2026-00004`
- **CWE:** Not assigned
- **Package:** `externum@4.3.0`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements a custom DRM (Digital Rights Management) system that includes obfuscation of string literals and runtime tamper detection. While these techniques are often used for security, they can also be used to hide malicious behavior or hinder security analysis. The code uses base64 encoding for string literals and performs runtime integrity checks on the file itself.

**Evidence:**
- `externum-4.3.0/externum/drm.py` — Implements _obfuscate_strings which encodes string literals in base64 and provides a runtime decoder, and _ext_drm_self_check which reads the file's own source code to verify its integrity.
- `externum-4.3.0/externum/runtime/__init__.py` — The Runtime class uses exec() on dynamically compiled code, which is a common pattern for transpilers but requires careful review when combined with DRM/obfuscation.

**Reviewer notes:**
- The DRM implementation is clearly intended for protecting intellectual property (license keys, watermarking).
- The self-tamper detection mechanism is a common technique in commercial software protection but is inherently suspicious in open-source packages as it can be used to prevent users from auditing or modifying the code.
- The use of exec() on generated code is standard for a language transpiler, but the combination with obfuscation makes static analysis of the final executed code difficult.

### Dynamic Runtime Dependency Installation in uag
- **Advisory:** `AUTH-2026-00005`
- **CWE:** `CWE-94`
- **Package:** `uag@0.7.14`
- **Severity:** `medium`
- **Confidence:** `0.7`
- **Review:** `PENDING`

The package implements a dynamic auto-installation mechanism that executes 'pip install' commands at runtime when optional dependencies are missing. While this is intended to improve user experience for optional features, it introduces risks related to arbitrary code execution and dependency confusion if not strictly controlled.

**Evidence:**
- `src/uagent/_pip_auto.py` — The 'auto_install' and 'install_with_status' functions use 'subprocess.run' to execute 'pip install' commands at runtime, which can be triggered by missing imports.
- `src/uagent/_pip_auto.py` — The '_ALLOWED_PACKAGES' set defines a large list of packages that the library is permitted to install automatically, which could be exploited if an attacker influences the environment or the package's dependency resolution.

**Reviewer notes:**
- The auto-installation feature is gated by an environment variable 'UAGENT_AUTO_INSTALL' (defaulting to 'allow'), which allows users to disable it. However, the default behavior is to permit automatic installation.
- The implementation attempts to verify the package after installation, but the reliance on 'pip' at runtime is a significant security concern for production environments.
- The package also includes cryptographic utilities for environment variable encryption, which appear to be implemented correctly using 'cryptography.hazmat' primitives.

## Omitted Results

97 result(s) were non-actionable, insufficient, or failed analysis and were not emitted as advisories.
