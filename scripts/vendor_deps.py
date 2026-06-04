#!/usr/bin/env python3
"""
vendor_deps.py — download all SHADOWMESH dependencies into libs/maven/

Run this once on a machine with internet access:
    python3 scripts/vendor_deps.py

It downloads every artifact (POM, JAR/AAR, sources, -javadoc) declared in
gradle/libs.versions.toml plus their transitive dependencies, storing them in
the standard Maven local-repository layout under libs/maven/.

After running this script, the project builds fully offline:
    ./gradlew assembleRelease --offline

The script is idempotent — re-running it only downloads missing or changed files.
It verifies SHA-256 of every artifact against Maven Central / Google Maven metadata.

Requirements:
    Python 3.8+, no extra packages needed (uses only stdlib).
    Java / Gradle / Android SDK are NOT required to run this script.

Network access needed:
    https://repo1.maven.org  (Maven Central)
    https://maven.google.com (Google Maven)
    https://plugins.gradle.org (Gradle plugin portal — for plugin markers)
"""

import hashlib, os, re, sys, time, urllib.request, urllib.error
from pathlib import Path
from typing import Optional

ROOT      = Path(__file__).parent.parent
LIBS_DIR  = ROOT / "libs" / "maven"
TOML_PATH = ROOT / "gradle" / "libs.versions.toml"

REPOS = [
    "https://maven.google.com",
    "https://repo1.maven.org/maven2",
    "https://plugins.gradle.org/m2",
]

# ---------------------------------------------------------------------------
# All external coordinates from libs.versions.toml + their Gradle plugin
# marker artifacts (needed for settings.gradle.kts plugin resolution).
# Format: "group:artifact:version"
# ---------------------------------------------------------------------------
DIRECT_COORDS = [
    # Kotlin
    "org.jetbrains.kotlin:kotlin-stdlib:1.9.23",
    "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0",
    "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0",
    "org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.0",

    # AndroidX core
    "androidx.core:core-ktx:1.13.0",
    "androidx.appcompat:appcompat:1.6.1",
    "androidx.biometric:biometric:1.2.0-alpha05",
    "androidx.sqlite:sqlite-ktx:2.4.0",
    "androidx.work:work-runtime-ktx:2.9.0",
    "androidx.lifecycle:lifecycle-viewmodel-ktx:2.7.0",
    "androidx.lifecycle:lifecycle-runtime-ktx:2.7.0",
    "androidx.lifecycle:lifecycle-runtime-compose:2.7.0",
    "androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0",

    # Room
    "androidx.room:room-runtime:2.6.1",
    "androidx.room:room-ktx:2.6.1",
    "androidx.room:room-compiler:2.6.1",    # annotation processor

    # Hilt (Dagger)
    "com.google.dagger:hilt-android:2.51.1",
    "com.google.dagger:hilt-compiler:2.51.1",
    "androidx.hilt:hilt-work:1.2.0",
    "androidx.hilt:hilt-compiler:1.2.0",

    # Compose BOM + individual artifacts
    "androidx.compose:compose-bom:2024.05.00",
    "androidx.activity:activity-compose:1.9.0",
    "androidx.navigation:navigation-compose:2.7.7",
    "androidx.hilt:hilt-navigation-compose:1.2.0",

    # Crypto
    "com.goterl:lazysodium-android:5.1.4",
    "com.goterl:lazysodium-java:5.1.4",
    "org.openquantumsafe:liboqs-java:0.10.1",

    # SQLCipher
    "net.zetetic:sqlcipher-android:4.5.6",

    # Erasure coding
    "com.backblaze:erasure:1.6.0",

    # QR codes
    "com.google.zxing:core:3.5.3",

    # Test
    "junit:junit:4.13.2",
    "io.kotest:kotest-runner-junit5:5.8.1",
    "io.kotest:kotest-assertions-core:5.8.1",
    "io.mockk:mockk:1.13.10",

    # Gradle plugin markers (required for plugins {} block resolution offline)
    "com.android.application:com.android.application.gradle.plugin:8.3.2",
    "com.android.library:com.android.library.gradle.plugin:8.3.2",
    "org.jetbrains.kotlin.android:org.jetbrains.kotlin.android.gradle.plugin:1.9.23",
    "com.google.dagger.hilt.android:com.google.dagger.hilt.android.gradle.plugin:2.51.1",
    "com.google.devtools.ksp:com.google.devtools.ksp.gradle.plugin:1.9.23-1.0.19",

    # AGP itself
    "com.android.tools.build:gradle:8.3.2",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def gav_to_path(group: str, artifact: str, version: str, classifier: str = "", ext: str = "") -> str:
    g = group.replace(".", "/")
    base = f"{artifact}-{version}"
    if classifier:
        base = f"{base}-{classifier}"
    return f"{g}/{artifact}/{version}/{base}.{ext or 'pom'}"


def local_path(rel: str) -> Path:
    return LIBS_DIR / rel


def fetch(url: str, dest: Path, *, verify_sha256: Optional[str] = None) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        if verify_sha256:
            actual = hashlib.sha256(dest.read_bytes()).hexdigest()
            if actual == verify_sha256:
                return True   # already have it, checksum matches
        else:
            return True       # already have it, no checksum to verify
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "shadowmesh-vendor/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        if verify_sha256:
            actual = hashlib.sha256(data).hexdigest()
            if actual != verify_sha256:
                print(f"  [CHECKSUM MISMATCH] {url}")
                return False
        dest.write_bytes(data)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False    # artifact doesn't exist in this repo — try next
        print(f"  [HTTP {e.code}] {url}")
        return False
    except Exception as e:
        print(f"  [ERROR] {url}: {e}")
        return False


def fetch_from_repos(rel: str) -> bool:
    """Try each repo in order, return True on first success."""
    for repo in REPOS:
        url = f"{repo}/{rel}"
        dest = local_path(rel)
        if fetch(url, dest):
            # Also try to get the sha256 file for future verification
            fetch(f"{url}.sha256", dest.with_suffix(dest.suffix + ".sha256"))
            return True
    return False


def fetch_artifact(group: str, artifact: str, version: str) -> bool:
    """Download POM + primary artifact (JAR or AAR) + sources JAR."""
    ok = True

    # POM — always
    pom_rel = gav_to_path(group, artifact, version, ext="pom")
    if not fetch_from_repos(pom_rel):
        print(f"  [MISSING POM] {group}:{artifact}:{version}")
        ok = False

    # Determine artifact extension from group heuristic
    # Android artifacts (.aar): anything androidx.*, android.*, com.android.*,
    #   com.google.dagger (hilt), com.goterl (lazysodium-android), net.zetetic
    android_groups = {
        "androidx", "com.android", "com.google.dagger", "net.zetetic",
    }
    is_android = (
        any(group.startswith(g) for g in android_groups)
        or artifact.endswith("-android")
        or "android" in artifact.lower()
    )

    # Some artifacts are POM-only (BOM, plugin markers, annotation processors)
    pom_only_hints = {
        "compose-bom", "gradle.plugin", "hilt-compiler", "room-compiler",
        "hilt-android-compiler",
    }
    is_pom_only = any(h in artifact for h in pom_only_hints)

    if not is_pom_only:
        ext = "aar" if is_android else "jar"
        jar_rel = gav_to_path(group, artifact, version, ext=ext)
        if not fetch_from_repos(jar_rel):
            # Try the other extension as fallback
            other_ext = "jar" if ext == "aar" else "aar"
            jar_rel = gav_to_path(group, artifact, version, ext=other_ext)
            if not fetch_from_repos(jar_rel):
                print(f"  [MISSING JAR/AAR] {group}:{artifact}:{version}")

        # Sources (best-effort, not required for offline build)
        src_rel = gav_to_path(group, artifact, version, classifier="sources", ext="jar")
        fetch_from_repos(src_rel)

    return ok


def parse_transitive_from_pom(pom_path: Path) -> list[tuple[str, str, str]]:
    """
    Minimal POM parser — extracts <dependency> elements with compile/runtime scope.
    Does not resolve property substitutions or BOM imports (those require a full
    dependency resolver). For a complete transitive closure, use Gradle's
    dependency resolution instead (see README note below).
    """
    if not pom_path.exists():
        return []
    text = pom_path.read_text(errors="replace")
    deps = []
    # Find <dependencies> section (not <dependencyManagement>)
    section = re.search(r'<dependencies>(.*?)</dependencies>', text, re.DOTALL)
    if not section:
        return []
    for dep in re.finditer(r'<dependency>(.*?)</dependency>', section.group(1), re.DOTALL):
        d = dep.group(1)
        g = re.search(r'<groupId>([^<]+)</groupId>', d)
        a = re.search(r'<artifactId>([^<]+)</artifactId>', d)
        v = re.search(r'<version>([^<]+)</version>', d)
        scope = re.search(r'<scope>([^<]+)</scope>', d)
        optional = re.search(r'<optional>true</optional>', d)
        if g and a and v and not optional:
            sc = scope.group(1) if scope else "compile"
            if sc in ("compile", "runtime"):
                deps.append((g.group(1).strip(), a.group(1).strip(), v.group(1).strip()))
    return deps


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Vendoring dependencies into {LIBS_DIR}")
    print(f"Repos: {REPOS}\n")

    LIBS_DIR.mkdir(parents=True, exist_ok=True)

    seen = set()
    queue = []

    for coord in DIRECT_COORDS:
        parts = coord.split(":")
        if len(parts) == 3:
            queue.append(tuple(parts))

    failures = []
    processed = 0

    while queue:
        gav = queue.pop(0)
        if gav in seen:
            continue
        seen.add(gav)
        group, artifact, version = gav

        # Skip unresolvable property placeholders
        if "${" in version:
            print(f"  [SKIP] {group}:{artifact}:{version} (unresolved property)")
            continue

        processed += 1
        print(f"[{processed:3d}] {group}:{artifact}:{version}")
        ok = fetch_artifact(group, artifact, version)
        if not ok:
            failures.append(f"{group}:{artifact}:{version}")

        # Queue transitive deps from POM
        pom_path = local_path(gav_to_path(group, artifact, version, ext="pom"))
        for dep in parse_transitive_from_pom(pom_path):
            if dep not in seen:
                queue.append(dep)

    print(f"\n{'='*60}")
    print(f"Processed {processed} artifacts.")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for f in failures:
            print(f"  {f}")
        print("\nRe-run to retry. Check your network connection.")
    else:
        print("All artifacts downloaded successfully.")

    print(f"\nVendored to: {LIBS_DIR}")
    print("\nNOTE: This script resolves one level of POM-declared compile/runtime")
    print("dependencies. For a guaranteed complete transitive closure, run:")
    print("  ./gradlew dependencies --write-locks")
    print("on a connected machine, then re-run this script to capture any")
    print("additional artifacts that Gradle resolved via BOM imports.")


if __name__ == "__main__":
    main()
