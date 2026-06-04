# libs/maven — Vendored Dependencies

This directory is a local Maven repository containing all external dependencies
required to build SHADOWMESH. When populated, the project builds completely
offline with no network access.

## Populating

Run this once on a machine with internet access (Python 3.8+, no extra packages):

```bash
python3 scripts/vendor_deps.py
```

The script downloads every artifact listed in `gradle/libs.versions.toml` plus
their transitive dependencies (POM-declared compile/runtime scope), storing
them in the standard `group/artifact/version/` Maven layout.

## Building offline

After populating:

```bash
./gradlew assembleRelease --offline
```

Gradle resolves all dependencies from `libs/maven/` first. Anything not found
there falls back to Google Maven and Maven Central (requires network).

## Verifying completeness

```bash
./gradlew dependencies --offline 2>&1 | grep "FAILED"
```

Any `FAILED` resolution means an artifact is missing. Re-run `vendor_deps.py`
to fetch it, then re-run the build.

## Air-gap builds

By default, binary artifacts (`.jar`, `.aar`, `.pom`) are excluded from git
via `.gitignore`. For a true air-gap build environment where the vendor machine
and build machine are different:

1. Remove or edit `libs/maven/.gitignore` to track binary artifacts.
2. Commit the populated `libs/maven/` directory.
3. The build machine needs no network access at all.

Alternatively, archive the directory and transfer it manually:

```bash
# On vendor machine:
tar -czf shadowmesh-deps.tar.gz libs/maven/

# On build machine:
tar -xzf shadowmesh-deps.tar.gz
```

## What's vendored

- All artifacts in `gradle/libs.versions.toml`
- Their transitive compile/runtime dependencies (resolved from POMs)
- Gradle plugin marker artifacts (for `plugins {}` block resolution)
- Sources JARs where available (for IDE navigation)

## Updating a dependency

1. Update the version in `gradle/libs.versions.toml`
2. Delete the old version's directory from `libs/maven/`
3. Re-run `python3 scripts/vendor_deps.py`
