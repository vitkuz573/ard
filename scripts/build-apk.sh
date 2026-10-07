#!/usr/bin/env bash
# Build dev.ard.agent as an APK without Gradle.
#
# Gradle is deliberately not used. This machine has build-tools and a platform but
# no Gradle, and more importantly a build with no dependency resolution is one that
# cannot break on a phone that has no WiFi, which is exactly the deployment this app
# exists to serve. The whole toolchain is aapt2, javac, d8, zipalign and apksigner.
#
# The agent binary is cross-compiled here and placed in assets, so a single APK
# carries everything needed to run it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
BUILD_TOOLS="$ANDROID_HOME/build-tools/34.0.0"
PLATFORM="$ANDROID_HOME/platforms/android-34/android.jar"
OUT="$ROOT/android/build"
APK="$ROOT/android/ard-agent.apk"

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk}"
PATH="$JAVA_HOME/bin:$PATH"

for tool in aapt2 d8 zipalign apksigner; do
  [[ -x "$BUILD_TOOLS/$tool" ]] || { echo "missing $BUILD_TOOLS/$tool" >&2; exit 1; }
done
[[ -f "$PLATFORM" ]] || { echo "missing $PLATFORM" >&2; exit 1; }

step() { printf '\n==> %s\n' "$1"; }

step "cross-compiling the agent for arm64"
mkdir -p "$OUT"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w" -o "$OUT/ard-agent" "$ROOT/cmd/ard-agent"
printf '    agent %s bytes\n' "$(stat -c%s "$OUT/ard-agent")"

step "compiling resources"
mkdir -p "$OUT/compiled" "$OUT/gen"
"$BUILD_TOOLS/aapt2" compile --dir "$ROOT/android/res" -o "$OUT/compiled/res.zip" 2>/dev/null \
  || { echo "note: no res/ directory, compiling without app resources"; }

step "linking resources and generating R.java"
LINK_ARGS=(-I "$PLATFORM" --manifest "$ROOT/android/AndroidManifest.xml"
           --java "$OUT/gen" --min-sdk-version 26 --target-sdk-version 34
           -o "$OUT/base.apk")
if [[ -f "$OUT/compiled/res.zip" ]]; then
  LINK_ARGS+=("$OUT/compiled/res.zip")
fi
"$BUILD_TOOLS/aapt2" link "${LINK_ARGS[@]}"
echo "    base.apk built"

step "compiling Java"
mkdir -p "$OUT/classes"
find "$ROOT/android/dev" -name '*.java' > "$OUT/sources.txt"
javac -classpath "$PLATFORM" -nowarn \
      -d "$OUT/classes" @"$OUT/sources.txt"
echo "    $(find "$OUT/classes" -name '*.class' | wc -l) classes"

step "dexing"
mkdir -p "$OUT/dex"
"$BUILD_TOOLS/d8" --lib "$PLATFORM" --min-api 26 --output "$OUT/dex" \
      $(find "$OUT/classes" -name '*.class')
echo "    classes.dex built"

step "packaging with the agent in assets"
# The agent goes in as a stored (uncompressed) entry. An app extracting a
# compressed 5 MB binary on every cold start is a visible delay, and compressed
# zips inside a zip are the usual source of "not executable" reports.
ZIPDIR="$OUT/zipdir"
rm -rf "$ZIPDIR"
mkdir -p "$ZIPDIR/lib/arm64-v8a"
cp "$OUT/base.apk" "$OUT/unaligned.apk"
cp "$OUT/dex/classes.dex" "$ZIPDIR/classes.dex"
# The agent ships as a NATIVE LIBRARY, not as an asset.
#
# /data/user/<n>/<pkg>/files is mounted noexec on every modern Android release, so a
# binary extracted there dies with error=13, Permission denied. nativeLibraryDir is
# the one app-writable directory that is deliberately exec-mounted, because it is
# where the platform itself puts executables. Naming the agent libardagent.so puts
# it there, and the .so suffix costs nothing: execve does not care what it is called.
cp "$OUT/ard-agent" "$ZIPDIR/lib/arm64-v8a/libardagent.so"
cd "$ZIPDIR"
zip -q -X "$OUT/unaligned.apk" classes.dex
# Compressed, unlike a plain asset: PackageManager extracts it once at install time
# and never again, so the size on disk does not matter and compression helps.
zip -q -X -9 "$OUT/unaligned.apk" lib/arm64-v8a/libardagent.so
cd "$ROOT"

step "aligning and signing"
"$BUILD_TOOLS/zipalign" -f -p 4 "$OUT/unaligned.apk" "$OUT/aligned.apk"
KS="$OUT/keystore.jks"
if [[ ! -f "$KS" ]]; then
  keytool -genkeypair -v -keystore "$KS" -storepass ardagent -keypass ardagent \
    -alias ard -keyalg EC -groupname secp256r1 -validity 10000 \
    -dname "CN=ARD Agent, O=ARD" >/dev/null 2>&1
  echo "    debug keystore created"
fi
"$BUILD_TOOLS/apksigner" sign \
  --ks "$KS" --ks-pass pass:ardagent --key-pass pass:ardagent \
  --out "$APK" "$OUT/aligned.apk"
"$BUILD_TOOLS/apksigner" verify --verbose "$APK" | tail -2

step "verifying the APK actually contains what the app reads"
# Build success is not the same as a usable artefact: an APK with no agent binary in it
# builds and signs fine, and the failure only surfaces on a phone as
# FileNotFoundException. The checks below assert the specific things the app depends on at
# runtime.
require_entry() {
  if ! unzip -l "$APK" | grep -qE "$1"; then
    echo "APK is missing $2" >&2
    echo "" >&2
    echo "contents:" >&2
    unzip -l "$APK" | sed 's/^/  /' >&2
    exit 1
  fi
  echo "    ok $2"
}
require_entry "lib/arm64-v8a/libardagent.so" "lib/arm64-v8a/libardagent.so"
require_entry "classes.dex"       "classes.dex"
require_entry "AndroidManifest.xml" "AndroidManifest.xml"
require_entry "classes[0-9]*\.dex" "dex"

# The binary inside the APK must be the ARM64 one. A wrong-ABI agent builds and
# signs fine and then refuses to run with "not executable: 64-bit ELF file".
MAGIC="$(unzip -p "$APK" lib/arm64-v8a/libardagent.so | od -An -tx1 -N 4 | tr -d ' \n')"
if [[ "$MAGIC" != "7f454c46" ]]; then
  echo "libardagent.so is not an ELF binary (magic=$MAGIC, want 7f454c46)" >&2
  exit 1
fi
echo "    ok agent binary is ELF"
ARCH="$(unzip -p "$APK" lib/arm64-v8a/libardagent.so | od -An -tx1 -j 18 -N 2 | tr -d ' ')"
if [[ "$ARCH" != "b700" ]]; then
  echo "assets/ard-agent is not AArch64 (e_machine=$ARCH, want b700)" >&2
  exit 1
fi
echo "    ok agent binary is AArch64"

"$BUILD_TOOLS/apksigner" verify "$APK" || { echo "signature does not verify" >&2; exit 1; }
echo "    ok signature verifies"

step "done"
printf '\nAPK ready: %s (%s)\n\n' "$APK" "$(du -h "$APK" | cut -f1)"
echo "Install with:  adb install -r $APK"
echo "The debug keystore is a build artefact only; never ship this key."