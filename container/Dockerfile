# Analysis image for MCP sandboxes. Must be linux/amd64: the sandbox-shim helper is amd64-only.
#
# Third-party tools that are not packaged in Debian are pinned by version and verified by SHA-256.
# To upgrade one, change its version and checksum together.
#
# The build writes /etc/sandbox-image.json (IMAGE_VERSION below plus every tool's version), which
# sandbox_status reports. Bump IMAGE_VERSION whenever this file changes.

# --- pycdc: Python bytecode decompiler, built from a pinned commit (the project has no releases).
FROM --platform=linux/amd64 debian:trixie-slim AS pycdc
ARG PYCDC_COMMIT=b4289760970dbc399684f1e155ec6d1ea1cc787e
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git cmake make g++ python3 \
  && git clone https://github.com/zrax/pycdc.git /src \
  && git -C /src checkout "$PYCDC_COMMIT" \
  && cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
  && cmake --build /build -j"$(nproc)" \
  && install -m 0755 /build/pycdc /build/pycdas /usr/local/bin/ \
  && printf '%s' "$PYCDC_COMMIT" > /pycdc.version

# --- Downloads, each verified against its checksum.
FROM --platform=linux/amd64 debian:trixie-slim AS downloads
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip
WORKDIR /dl
RUN <<'EOF'
set -eu
fetch() { curl -fsSL -o "$1" "$3" && echo "$2  $1" | sha256sum -c -; }
CFR=0.152 VINEFLOWER=1.12.0 APKTOOL=3.0.3 JADX=1.5.6 CAPA=9.4.0 FLOSS=3.1.1 RADARE2=6.2.4 DIE=3.21
PYINSTXTRACTOR=2026.07 DIDIER=b248e9aabac4dedc2619c986d07eb7a5f4c18d37
GH=https://github.com
DS=https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/$DIDIER
fetch cfr.jar           f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2 "$GH/leibnitz27/cfr/releases/download/$CFR/cfr-$CFR.jar"
fetch vineflower.jar    1dfcfe974395734fa467ce620661c7623d05ba83670de0529b1fbd63ff548b9d "$GH/Vineflower/vineflower/releases/download/$VINEFLOWER/vineflower-$VINEFLOWER.jar"
fetch apktool.jar       dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423 "$GH/iBotPeaches/Apktool/releases/download/v$APKTOOL/apktool_$APKTOOL.jar"
fetch jadx.zip          545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974 "$GH/skylot/jadx/releases/download/v$JADX/jadx-$JADX.zip"
fetch capa.zip          07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4 "$GH/mandiant/capa/releases/download/v$CAPA/capa-v$CAPA-linux.zip"
fetch floss.zip         40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666 "$GH/mandiant/flare-floss/releases/download/v$FLOSS/floss-v$FLOSS-linux.zip"
fetch radare2.deb       7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90 "$GH/radareorg/radare2/releases/download/$RADARE2/radare2_${RADARE2}_amd64.deb"
fetch die.deb           cf6078edce2403bf73584a284cc8aaba122c38a53c91560e136fc98c5ca6a648 "$GH/horsicq/DIE-engine/releases/download/$DIE/die_${DIE}_Debian_12_amd64.deb"
fetch pyinstxtractor.py 94e0b6c9d5151bbeefc7e7452e96e24b396c2dbfcb0348e5f12c4c0865fefe58 "https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/$PYINSTXTRACTOR/pyinstxtractor.py"
fetch pdfid.py          e958a01f1c2596470f27d3c308061b85d7059ff476a58d74f1957a71b4f1248f "$DS/pdfid.py"
fetch pdf-parser.py     a9fa2faa25e88ab0293543d14aa168ff21fc9fd25a0a8ad657b0dad3171214ac "$DS/pdf-parser.py"
fetch oledump.py        9a18a2b5ab877be8d86d218b8933933ce2be9dfd3cdcb1d971da5e27765b73eb "$DS/oledump.py"
mkdir -p /opt/tools/bin /opt/tools/java /opt/tools/py
printf '{"cfr":"%s","vineflower":"%s","apktool":"%s","jadx":"%s","capa":"%s","floss":"%s","radare2":"%s","die":"%s","pyinstxtractor":"%s","didier-stevens-suite":"%s"}' \
  "$CFR" "$VINEFLOWER" "$APKTOOL" "$JADX" "$CAPA" "$FLOSS" "$RADARE2" "$DIE" "$PYINSTXTRACTOR" "$(printf %.12s "$DIDIER")" \
  > /opt/tools/versions.json
unzip -q jadx.zip -d /opt/tools/jadx
unzip -q capa.zip -d /opt/tools/bin
unzip -q floss.zip -d /opt/tools/bin
mv cfr.jar vineflower.jar apktool.jar /opt/tools/java/
mv pyinstxtractor.py pdfid.py pdf-parser.py oledump.py /opt/tools/py/
mv radare2.deb die.deb /opt/tools/
EOF

# --- Final image.
FROM --platform=linux/amd64 debian:trixie-slim
ARG IMAGE_VERSION=2026.10.15
LABEL org.opencontainers.image.version=$IMAGE_VERSION

# Helper binary used by @cloudflare/sandbox (Files, DirectoryBackup). The tag must match the
# installed @cloudflare/sandbox version in package.json.
COPY --from=docker.io/cloudflare/sandbox:1.0.1 /usr/local/bin/sandbox-shim /usr/local/bin/sandbox-shim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

COPY --from=downloads /opt/tools /opt/tools

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
  # base tooling
  tini ca-certificates coreutils procps psmisc less jq git curl xxd bsdextrautils sqlite3 ripgrep \
  # static analysis
  file binutils elfutils patchelf yara libimage-exiftool-perl ssdeep upx-ucl binwalk osslsigncode \
  # archives and installers (samples often come as encrypted zips: 7z x -pinfected)
  7zip unzip zip unar xz-utils zstd lzip cabextract innoextract msitools \
  # Java and Android: javap, jar, and the runtime for CFR, Vineflower, jadx and apktool
  default-jdk-headless \
  # documents
  qpdf poppler-utils \
  # network captures
  tshark tcpdump \
  # dynamic analysis
  strace ltrace gdb \
  # scripting (node is for JavaScript malware; samples run offline here)
  python3 python3-venv nodejs \
  # radare2 and Detect It Easy, with their dependencies
  /opt/tools/radare2.deb /opt/tools/die.deb \
  && rm -rf /var/lib/apt/lists/* /opt/tools/*.deb

RUN python3 -m venv /opt/venv \
  && /opt/venv/bin/pip install --no-cache-dir \
  pefile dnfile pyelftools lief capstone yara-python oletools pycryptodome \
  python-magic pyzipper xdis speakeasy-emulator \
  # speakeasy's old unicorn imports distutils and pkg_resources; setuptools<81 still provides both
  'setuptools<81'

COPY --from=pycdc /usr/local/bin/pycdc /usr/local/bin/pycdas /usr/local/bin/
COPY --from=pycdc /pycdc.version /opt/tools/pycdc.version

# Command-line wrappers so every tool is on PATH under its usual name.
RUN <<'EOF'
set -eu
for jar in cfr vineflower apktool; do
  printf '#!/bin/sh\nexec java -jar /opt/tools/java/%s.jar "$@"\n' "$jar" > "/usr/local/bin/$jar"
done
for script in pyinstxtractor pdfid pdf-parser oledump; do
  printf '#!/bin/sh\nexec python3 /opt/tools/py/%s.py "$@"\n' "$script" > "/usr/local/bin/$script"
done
chmod 0755 /usr/local/bin/cfr /usr/local/bin/vineflower /usr/local/bin/apktool \
  /usr/local/bin/pyinstxtractor /usr/local/bin/pdfid /usr/local/bin/pdf-parser /usr/local/bin/oledump
ln -s /opt/tools/jadx/bin/jadx /usr/local/bin/jadx
ln -s /opt/tools/bin/capa /usr/local/bin/capa
ln -s /opt/tools/bin/floss /usr/local/bin/floss
EOF

ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Version manifest for sandbox_status, written on one line. Packages that are missing are left out.
RUN IMAGE_VERSION="$IMAGE_VERSION" /opt/venv/bin/python -I - <<'EOF'
import datetime, importlib.metadata, json, os, subprocess

tools = json.load(open('/opt/tools/versions.json'))
tools['pycdc'] = open('/opt/tools/pycdc.version').read().strip()[:12]
packages = subprocess.run(
    ['dpkg-query', '-W', '-f', '${db:Status-Abbrev}\t${Package}\t${Version}\n', 'radare2', 'detectiteasy', 'yara', 'ssdeep', 'upx-ucl', 'binwalk',
     'osslsigncode', 'binutils', 'file', 'gdb', 'strace', 'ltrace', 'libimage-exiftool-perl', '7zip', 'unar',
     'cabextract', 'innoextract', 'msitools', 'openjdk-*-jdk-headless', 'qpdf', 'poppler-utils', 'tshark',
     'tcpdump', 'python3', 'nodejs', 'ripgrep', 'jq', 'sqlite3'],
    capture_output=True, text=True,
).stdout
python = {}
for name in ['pefile', 'dnfile', 'pyelftools', 'lief', 'capstone', 'yara-python', 'oletools', 'pycryptodome',
             'python-magic', 'pyzipper', 'xdis', 'speakeasy-emulator']:
    try:
        python[name] = importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        pass
manifest = {
    'version': os.environ['IMAGE_VERSION'],
    'built': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'debian': open('/etc/debian_version').read().strip(),
    'tools': tools,
    # Patterns also list known but uninstalled packages; keep the installed ones ("ii").
    'packages': {
        fields[1]: fields[2] for fields in (line.split('\t') for line in packages.splitlines())
        if len(fields) == 3 and fields[0].startswith('ii')
    },
    'python': python,
}
with open('/etc/sandbox-image.json', 'w') as f:
    json.dump(manifest, f, separators=(',', ':'))
EOF

RUN mkdir -p /workspace /var/lib/sandbox/jobs
WORKDIR /workspace

# The Durable Object starts the container with `tini -s -- sleep infinity`: tini reaps the
# orphans that background jobs leave behind, so killed jobs do not linger as zombies.
CMD ["/usr/bin/tini", "-s", "--", "sleep", "infinity"]
