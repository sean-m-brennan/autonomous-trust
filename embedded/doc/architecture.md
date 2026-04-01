# Embedded Deployment System Architecture

## 1. Overview

AutonomousTrust is a high-trust cooperative computing framework -- a data messaging system where encrypted data is shared only with trusted peers based on fine-grained, dynamically-evaluated trust scores. The framework uses NaCl/libsodium cryptography and implements dynamic composability of microservices with security at its core.

The embedded deployment system targets resource-constrained IoT devices: Raspberry Pi 4, Compute Module 4, industrial gateways, and embedded Linux platforms. Its purpose is push-button deployment with minimal supply chain attack surface.

The system provides two deployment tiers:

- **Phase 1 (Bare-metal systemd service):** SSH to a device, run one script, node is live. Uses the `at_demo` C binary with shared library dependencies on a standard Debian-based OS. Suitable for development and non-security-critical deployments.

- **Phase 4 (Hardened minimal OS image):** Flash an SD card, insert, power on. True zero-touch deployment. The image contains a fully static `at_demo` binary on a dm-verity-protected, minimal Buildroot Linux. No runtime shared libraries, no shell post-provisioning, no SSH. Every byte in the image is accounted for.

The motivation for Phase 4 is that for a trust framework, supply chain compromise is existential -- it undermines the product's core value proposition. The hardened image captures approximately 80% of a unikernel's supply chain benefit at approximately 10% of the implementation cost, and works on target hardware today.

## 2. Architecture Diagram

### Build Pipeline

```
+------------------+     +-------------------+     +--------------------+
|   C Source Code  |     | Dockerfile-c-     |     | build-arm.sh       |
|   src/c/         | --> | static            | --> | --static           |
|   src/protobuf/  |     | (Docker buildx)   |     | (cross-compile)    |
+------------------+     +-------------------+     +--------------------+
                                                          |
                                                          v
                                                   +--------------------+
                                                   | at_demo            |
                                                   | (static ELF,      |
                                                   |  arm64 or amd64)  |
                                                   +--------------------+
                                                          |
                                                          v
                                                   +--------------------+
                                                   | sign-binary.sh     |
                                                   | (Ed25519 via       |
                                                   |  openssl)          |
                                                   +--------------------+
                                                          |
                                                          v
+------------------+     +-------------------+     +--------------------+
| Buildroot        |     | buildroot/        |     | build-image.sh     |
| 2024.02.10       | <-- | Dockerfile        | <-- | (orchestrator)     |
| (in Docker)      |     | at_defconfig      |     |                    |
+------------------+     | kernel.defconfig  |     +--------------------+
       |                  | post-build.sh     |
       |                  | post-image.sh     |
       |                  | rootfs-overlay/   |
       |                  +-------------------+
       v
+------------------+     +-------------------+     +--------------------+
| rootfs.ext4 (ro) | --> | dm-verity hash    | --> | SD card image      |
| + kernel + DTB   |     | tree generation   |     | autonomous-trust   |
| + U-Boot         |     | (veritysetup)     |     | .img               |
+------------------+     +-------------------+     +--------------------+
                                                          |
                                                          v
                                                   +--------------------+
                                                   | flash.sh           |
                                                   | (dd to /dev/sdX)   |
                                                   +--------------------+
```

### SD Card Partition Layout

```
+------------------------------------------------------------------+
|  MBR  |  Part 1 (FAT32)  |  Part 2 (ext4, ro)  |  Part 3 (ext4) |
|       |  Boot: 64 MB     |  Root: 128 MB+       |  Data: 64 MB   |
|       |  config.txt      |  dm-verity protected  |  /opt/at/      |
|       |  u-boot.bin      |  at_demo (static)    |  configs, keys  |
|       |  Image (kernel)  |  systemd (minimal)   |  logs, state    |
|       |  DTBs            |  busybox (1st boot)  |                 |
+------------------------------------------------------------------+
```

## 3. Security Model

### Supply Chain Threat Model

The relevant attack vectors for a trust framework's embedded deployment:

1. **Compromised upstream library source** -- attacker injects code into libsodium, protobuf-c, or other dependencies at the source repo level.
2. **Compromised package repository/mirror** -- MITM or compromised Debian mirror serves tampered `.deb` packages.
3. **Compromised build toolchain** -- compiler or linker backdoor (cf. Thompson's "Reflections on Trusting Trust").
4. **Compromised base image** -- Docker Hub or cloud image contains malicious code.
5. **Runtime exploitation of unnecessary services** -- attacker exploits SSH, shell, package manager, or other services not needed by `at_demo`.
6. **Tampered binary on device** -- attacker with physical or remote access modifies the binary or configuration files.

### Trust Chain

The boot trust chain on Pi4/CM4:

```
Pi4 EEPROM (OTP fuse)
    |
    v
Signed boot.img (kernel + initramfs + dm-verity root hash)
    |
    v
dm-verity verifies rootfs (every block read checked against hash tree)
    |
    v
at_demo starts (signature verified)
```

- The Pi4 EEPROM can be locked to boot only signed `boot.img` files.
- The initramfs sets up dm-verity before mounting the root filesystem.
- The root hash is embedded in the signed initramfs, making it tamper-evident.
- Compromising any layer requires breaking the signature chain.

### What Is Excluded from the Image (and Why)

| Excluded Component | Rationale |
|--------------------|-----------|
| Package manager (apt, opkg) | Eliminates runtime package supply chain; prevents unauthorized software installation |
| SSH daemon | Replaced by AT fleet management (Phase 5); removes remote access attack surface |
| Shell (post-provisioning) | Busybox is present for first boot only; prevents lateral movement via shell |
| Compiler, interpreter, debug tools | No on-device code execution capability for attackers |
| Man pages, docs, locales | Reduces image size and eliminates unnecessary files |
| Unnecessary kernel modules | Custom defconfig disables sound, DRM, framebuffer, HID, wireless, Bluetooth, NFS, CIFS |

### Supply Chain Spectrum

```
Full Debian  <--  Docker  <--  Static binary  <--  Minimal Linux (Buildroot)  <--  Unikernel  <--  seL4
     most flexible                                                                     smallest TCB
     largest attack surface                                                            least flexible
     ~150+ packages                    ~15 packages                    ~5 packages     formally verified
```

Phase 1 sits at the "Static binary on Full Debian" point. Phase 4 sits at the "Minimal Linux (Buildroot)" point.

### dm-verity Details

The root filesystem uses dm-verity for block-level integrity verification:

1. Buildroot produces a read-only ext4 root filesystem image.
2. `veritysetup format` generates a Merkle hash tree over the image (SHA-256).
3. The root hash (64 hex characters) is stored in `root-hash.txt` and embedded in the signed initramfs.
4. At boot, the kernel's device-mapper verity target checks every block read against the hash tree.
5. Any tampered block causes an I/O error -- the system refuses to run from a modified filesystem.

The kernel config enables `CONFIG_DM_VERITY=y` and `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y`.

Writable state (AT config, identity keys, logs) lives on a separate data partition at `/opt/autonomous-trust` (partition 3). This partition is not covered by dm-verity, but its contents are integrity-protected by AT's own NaCl signatures.

### Binary Signing Details

Binary signing uses Ed25519 via OpenSSL (available in OpenSSL 1.1.1+):

- **Key generation:** `openssl genpkey -algorithm Ed25519` produces a PEM private key. The public key is extracted with `openssl pkey -pubout`.
- **Signing:** `openssl pkeyutl -sign -inkey signing.key -rawin -in at_demo -out at_demo.sig` produces a detached signature.
- **Verification:** `openssl pkeyutl -verify -pubin -inkey signing.pub -rawin -in at_demo -sigfile at_demo.sig` returns exit code 0 on success.
- The signing key is the initial trust root; Phase 5's consensus mechanism can rotate it.

Ed25519 was chosen over NaCl's `crypto_sign` directly because `openssl` is a portable CLI tool available in build environments without requiring a custom C program for signing. The underlying algorithm is identical (Ed25519/RFC 8032).

## 4. Phase Summary

### Phase 1: Bare-Metal systemd Service -- Implemented

SSH to an ARM device, run one script, node is live. Uses the `at_demo` C binary with 6 shared library dependencies on a Debian-based OS. RAM footprint: 20-50 MB.

**Implemented files:** `embedded/build-arm.sh`, `embedded/install.sh`, `embedded/provision.sh`, `embedded/test-qemu.sh`, `embedded/autonomous-trust.service`.

### Phase 2: Docker Compose -- Planned

For devices that already run Docker. A single-node `docker-compose.yml` with `network_mode: host`, the `autonomous-trust-c` multi-arch image, and a volume mount for persistent config. Not yet implemented.

### Phase 3: Unikraft Unikernel -- Future R&D

Minimal-footprint deployment on KVM-capable edge hardware. Prior work exists in `embedded-trust/` (Python 3.7.4 unikernel with PyNaCl/libsodium). Current assessment: best suited for KVM/Xen environments, not bare-metal Pi. No major unikernel framework has production-ready bare-metal ARM support. Requires a Linux KVM host, which reintroduces supply chain surface.

### Phase 4: Hardened Minimal OS Image -- Implemented

Flash SD card, insert, power on. Zero-touch deployment. Fully static binary on a dm-verity-protected Buildroot Linux. Approximately 15 packages total (versus 150+ for Debian minimal). Zero runtime shared libraries.

**Implemented files:** `src/autonomous-trust/Dockerfile-c-static`, `embedded/build-image.sh`, `embedded/sign-binary.sh`, `embedded/verify-binary.sh`, `embedded/verify-image.sh`, `embedded/flash.sh`, `embedded/buildroot/Dockerfile`, `embedded/buildroot/at_defconfig`, `embedded/buildroot/kernel.defconfig`, `embedded/buildroot/post-build.sh`, `embedded/buildroot/post-image.sh`, `embedded/buildroot/rootfs-overlay/`.

### Phase 5: Decentralized Fleet Management -- Planned

The mesh manages itself using AT's existing trust, negotiation, and reputation machinery. Software updates are proposed, verified, voted on via Paxos consensus, distributed peer-to-peer, and rolled back automatically if health checks fail. No central server. Estimated effort: 3-4 weeks building on existing AT infrastructure.

## 5. Component Reference

| File | Purpose | Inputs | Outputs |
|------|---------|--------|---------|
| `embedded/build-arm.sh` | Cross-compile `at_demo` for ARM64 (and optionally AMD64) via `docker buildx`. Supports `--static` for fully static builds. | Source code in `src/c/`, `src/protobuf/`; `Dockerfile-c` or `Dockerfile-c-static` | `embedded/dist/autonomous-trust-{arch}.tar.gz` or `autonomous-trust-{arch}-static.tar.gz` |
| `embedded/build-image.sh` | Orchestrate the full Phase 4 build: static binary, optional signing, Buildroot in Docker, dm-verity, SD card image assembly. | Static binary from `build-arm.sh --static`; Buildroot configs in `embedded/buildroot/` | `embedded/dist/autonomous-trust.img`, `embedded/dist/root-hash.txt` |
| `embedded/install.sh` | Install AT on a bare-metal Linux device. Detects architecture, installs runtime deps via apt, deploys binary, enables systemd service. | Architecture-specific tarball from `build-arm.sh` | Binary at `/usr/local/bin/at_demo`, library at `/usr/local/lib/`, systemd service enabled |
| `embedded/provision.sh` | Generate provisioning configs for a fleet of N nodes. Produces per-node bootstrap configs with peer addresses and optional full identity pre-generation. | `--nodes N`, `--subnet CIDR`; optionally `at_demo` in PATH for `--full-identity` | Per-node tarballs in `embedded/fleet-configs/` containing bootstrap configs and environment files |
| `embedded/sign-binary.sh` | Sign `at_demo` with an Ed25519 key. Can generate a new keypair on first use. | Binary file, Ed25519 private key (PEM) | Detached signature file (`at_demo.sig`) |
| `embedded/verify-binary.sh` | Verify an `at_demo` binary signature against a public key. | Binary file, signature file (`.sig`), Ed25519 public key (PEM) | Exit code 0 (valid) or 1 (invalid) |
| `embedded/verify-image.sh` | 21-point verification of a built SD card image without booting it. Checks partition layout, boot contents, rootfs contents, dm-verity, binary signature, and sizes. | Buildroot output images directory; optional public key for signature check | Pass/fail report with counts |
| `embedded/flash.sh` | Write an `.img` file to an SD card with safety checks. Refuses system disks, verifies image fits on device, requires user confirmation. | `.img` file, block device path (e.g., `/dev/sdb`) | Written SD card |
| `embedded/test-qemu.sh` | End-to-end test using QEMU VMs. Spins up N Debian VMs on a shared virtual LAN, deploys via `install.sh` + `provision.sh`, verifies multi-node discovery. | `build-arm.sh` output (amd64 tarball); Debian cloud image (downloaded) | Pass/fail verification report; VMs with AT running |
| `embedded/autonomous-trust.service` | systemd unit file for the `at_demo` service. Configures environment, startup delay, restart policy, and systemd hardening (NoNewPrivileges, ProtectSystem, etc.). | N/A (declarative config) | N/A (consumed by systemd) |
| `embedded/buildroot/Dockerfile` | Reproducible Buildroot build environment. Installs all host dependencies, downloads Buildroot 2024.02.10. Based on `debian:bookworm`. | `BR_VERSION` build arg | Docker image `at-buildroot` with Buildroot source at `/buildroot` |
| `embedded/buildroot/at_defconfig` | Buildroot defconfig for the hardened Pi4/CM4 image. Targets aarch64 Cortex-A72, uses musl libc, systemd init, minimal busybox, dm-verity packages, U-Boot bootloader. | N/A (declarative config) | N/A (consumed by Buildroot `make defconfig`) |
| `embedded/buildroot/kernel.defconfig` | Minimal Linux kernel config based on `bcm2711_defconfig`. Enables dm-verity, networking (IPv4/IPv6/multicast/UDP), MMC, USB, virtio (QEMU testing). Disables sound, DRM, framebuffer, HID, wireless, Bluetooth, NFS, debug. | N/A (declarative config) | N/A (consumed by Buildroot kernel build) |
| `embedded/buildroot/post-build.sh` | Buildroot post-build hook. Verifies `at_demo` is in the overlay, sets permissions, creates data partition mount point, writes `/etc/fstab` (rootfs read-only, data partition read-write), strips man/doc/locale. | Buildroot target rootfs directory | Modified rootfs with fstab, permissions, stripped docs |
| `embedded/buildroot/post-image.sh` | Buildroot post-image hook. Generates dm-verity hash tree via `veritysetup format`, assembles FAT32 boot partition (Pi firmware, U-Boot, kernel, DTBs, config.txt), creates data partition, assembles final 3-partition SD card image via `sfdisk` + `dd`. | Buildroot images directory (rootfs.ext4, Image, DTBs, u-boot.bin, rpi-firmware) | `autonomous-trust.img`, `root-hash.txt`, `verity.table`, `boot.vfat`, `data.ext4` |
| `embedded/buildroot/rootfs-overlay/etc/systemd/system/autonomous-trust.service` | Copy of the systemd service file placed into the Buildroot rootfs overlay. Identical to `embedded/autonomous-trust.service`. | N/A | N/A (baked into rootfs) |
| `src/autonomous-trust/Dockerfile-c-static` | Multi-stage Docker build producing a fully static `at_demo`. Stage 1 builds with `clang`, `-DAT_STATIC=ON`, linking libsodium, libjansson, libuuid, protobuf-c statically. Stage 2 verifies `ldd` reports "not a dynamic executable". | `src/c/`, `src/protobuf/`, `GIT_VERSION` build arg | Docker image with static `at_demo` at `/usr/local/bin/at_demo` |

## 6. Boot Flow

Step-by-step from power-on to `at_demo` running on a Pi4 with the Phase 4 image:

1. **Pi4 EEPROM loads boot partition.** The EEPROM reads the FAT32 partition (partition 1) from the SD card at `/dev/mmcblk0p1`.

2. **config.txt directs to U-Boot.** The Pi firmware reads `config.txt` which specifies `arm_64bit=1`, `kernel=u-boot.bin`, `enable_uart=1`, and `dtoverlay=disable-bt`.

3. **U-Boot loads kernel and DTB.** U-Boot (built from Buildroot with `rpi_4` defconfig) loads the `Image` kernel file and the appropriate device tree blob (`bcm2711-rpi-4-b.dtb` or `bcm2711-rpi-cm4-io.dtb`).

4. **Kernel boots, initramfs sets up dm-verity.** The kernel starts, and the initramfs configures the device-mapper verity target using the embedded root hash. The `veritysetup` command maps `/dev/mmcblk0p2` through dm-verity, creating a verified block device.

5. **Root filesystem mounted read-only.** The verified root filesystem is mounted read-only at `/`. The data partition (`/dev/mmcblk0p3`) is mounted read-write at `/opt/autonomous-trust` per `/etc/fstab`.

6. **systemd starts `autonomous-trust.service`.** systemd reaches `multi-user.target`, which triggers the `autonomous-trust.service` unit. The `ExecStartPre` directives create `/opt/autonomous-trust/etc/at` and `/opt/autonomous-trust/var/at` if they do not exist, and apply any configured startup delay.

7. **`at_demo --generate-config` creates identity.** On first boot, `at_demo` generates a NaCl identity keypair and network configuration in `/opt/autonomous-trust/etc/at/`. If provisioned configs from `provision.sh` are present, the node uses those for peer discovery.

8. **Node joins AT mesh.** `at_demo` begins UDP multicast peer discovery, identity exchange, and trust negotiation with other nodes on the local network.

## 7. Build Flow

Step-by-step from source code to flashable `.img`:

### Step 1: Cross-compile static binary

```
embedded/build-arm.sh --static
```

- Uses `docker buildx build --platform linux/arm64` with `src/autonomous-trust/Dockerfile-c-static`.
- The Dockerfile installs build tools and `-dev` packages with static `.a` archives.
- CMake is invoked with `-DAT_STATIC=ON`, which sets `CMAKE_FIND_LIBRARY_SUFFIXES` to `.a` and adds `-static` to linker flags.
- The binary is built with `clang`, linking libsodium, libjansson, libuuid, and protobuf-c statically.
- Output: `embedded/dist/autonomous-trust-arm64-static.tar.gz` containing `usr/local/bin/at_demo`.

### Step 2: Sign binary (optional)

```
embedded/sign-binary.sh --binary dist/at_demo-arm64-static --key signing.key
```

- If no signing key exists, `--generate-key` creates an Ed25519 keypair via `openssl genpkey -algorithm Ed25519`.
- Signs the binary with `openssl pkeyutl -sign -inkey signing.key -rawin`.
- Output: `at_demo.sig` (detached Ed25519 signature).

### Step 3: Build Buildroot image

```
embedded/build-image.sh [--sign]
```

- Checks available disk space (requires 5+ GB).
- Calls `build-arm.sh --static` if no static binary exists (skippable with `--skip-binary`).
- Builds the Buildroot Docker image from `embedded/buildroot/Dockerfile` (pins Buildroot 2024.02.10 and all host dependencies).
- Copies the static binary into `embedded/buildroot/rootfs-overlay/usr/local/bin/at_demo`.
- Runs Buildroot inside Docker with mounted configs and build cache:
  - Loads `at_defconfig` (aarch64, Cortex-A72, musl, systemd, minimal busybox, dm-verity packages, U-Boot for Pi4).
  - Builds kernel 6.6 with `kernel.defconfig` (Pi4 + dm-verity + virtio).
  - `post-build.sh` runs: verifies `at_demo` in overlay, writes `/etc/fstab` (rootfs ro, data rw), strips docs.
  - `post-image.sh` runs: generates dm-verity hash tree, assembles boot partition (FAT32 with Pi firmware, U-Boot, kernel, DTBs, config.txt), creates data partition (ext4), assembles 3-partition SD card image via `sfdisk` + `dd`.
- Output: `embedded/dist/autonomous-trust.img`, `embedded/dist/root-hash.txt`.

### Step 4: Verify image

```
embedded/verify-image.sh
```

- Runs 21 checks without booting the image:
  - Partition layout (3 partitions: FAT32 boot, Linux rootfs, Linux data).
  - Boot partition contents (config.txt, u-boot.bin, kernel Image, DTBs).
  - Rootfs contents (at_demo binary, systemd service, service enabled, data mount point, fstab read-only).
  - Static linking verification (`file` shows "statically linked", architecture is ARM64).
  - No package manager (no apt-get, no dpkg).
  - dm-verity (root hash file, verity table, rootfs-verity.ext4 image; optional `veritysetup verify`).
  - Binary signature (if public key and .sig are present).
  - Size summary.
- Output: pass/fail count and detailed report.

### Step 5: Flash to SD card

```
sudo embedded/flash.sh embedded/dist/autonomous-trust.img /dev/sdX
```

- Validates the target is a block device, not a system disk (`/dev/sda`, `/dev/nvme0n1`, `/dev/vda`, `/dev/mmcblk0` are refused).
- Checks image fits on the target device.
- Requires explicit `yes` confirmation.
- Writes with `dd bs=4M status=progress conv=fsync`, then `sync`.

## 8. Decision Record

### Why Buildroot over pi-gen/Yocto

`pi-gen` builds Raspberry Pi OS, which is Debian-based. It carries the full Debian supply chain; stripping it down fights the tool rather than using it as intended. The resulting image still contains approximately 150+ packages.

Yocto is powerful but heavy: steep learning curve, long build times, and a complex layer system. It is overkill for a single-binary appliance.

Buildroot is designed for exactly this use case: minimal embedded Linux images with explicit package selection, reproducible builds, and cross-compilation. The `at_defconfig` file declares every component. The image contains approximately 15 packages: kernel, busybox (first-boot only), systemd (minimal), dm-verity tools, U-Boot, Pi firmware, and `at_demo`.

### Why static linking over dynamic

Phase 1 uses 6 shared libraries at runtime: libsodium, libjansson, libuuid, libprotobuf-c, libprotobuf, plus network tools. Each shared library is an attack surface -- it comes from a package repository and can be replaced on the device.

A fully static binary eliminates the runtime library supply chain entirely. The binary has zero `.so` dependencies. `ldd at_demo` reports "not a dynamic executable". The build pins library versions at compile time inside a Docker container, and the resulting binary is self-contained.

The trade-off is larger binary size and inability to update individual libraries without rebuilding. For a single-purpose appliance, this trade-off is favorable.

### Why Ed25519 via openssl (not NaCl directly)

`at_demo` uses NaCl/libsodium internally for Ed25519 operations. However, the signing scripts need a standalone CLI tool that works in build environments without requiring a custom C program.

OpenSSL 1.1.1+ supports Ed25519 natively via `openssl genpkey` and `openssl pkeyutl`. The underlying algorithm is identical (Ed25519 per RFC 8032). Using `openssl` keeps the signing pipeline portable and auditable without introducing additional build dependencies.

### Why musl over glibc

The Buildroot defconfig specifies `BR2_TOOLCHAIN_BUILDROOT_MUSL=y`. musl libc produces smaller binaries and has a simpler, more auditable codebase than glibc. For a statically linked single-binary appliance, musl's smaller footprint reduces the Trusted Computing Base. musl is the standard choice for minimal embedded Linux images built with Buildroot.

### The unikernel analysis -- why not now, what would change that

Unikraft (the leading unikernel framework) targets KVM/Xen/Firecracker. No upstream bare-metal platform driver exists. Running Unikraft on Pi4 requires a Linux KVM host, which reintroduces the supply chain surface the unikernel was meant to eliminate.

No major unikernel framework (MirageOS, OSv, IncludeOS, Rumprun) has production-ready bare-metal ARM support. A bare-metal Unikraft platform driver for ARM is non-trivial R&D, not configuration.

Prior work exists in `embedded-trust/` (Python 3.7.4 unikernel with PyNaCl/libsodium), but Python 3.7.4 is EOL, the current codebase requires 3.13, and the C-only unikernel path is only at hello-world proof-of-concept stage.

What would change that: (1) Unikraft or another framework shipping a bare-metal ARM platform driver; (2) the C unikernel path being built out with full `at_demo` support; (3) edge gateways with KVM capability becoming the primary deployment target (Phase 3 path).

### Why dm-verity over other integrity mechanisms

dm-verity provides block-level integrity verification with kernel-level enforcement. Alternatives considered:

- **IMA/EVM (Integrity Measurement Architecture):** File-level, not block-level. Requires per-file signatures and an extended attribute filesystem. More complex to set up and has a larger runtime overhead for whole-filesystem protection.
- **fs-verity:** File-level Merkle trees. Good for individual file verification but does not protect the entire filesystem layout (directory structure, permissions, etc.).
- **Full disk encryption (LUKS):** Provides confidentiality but not integrity. A tampered encrypted block decrypts to garbage but does not prevent the system from attempting to use it.

dm-verity provides the strongest whole-filesystem integrity guarantee with minimal runtime overhead. The hash tree is generated once at build time, and verification is transparent to userspace. The kernel refuses to read any tampered block, making it impossible for the system to run from a modified filesystem.

### Why no SSH post-provisioning

SSH is a remote access mechanism -- and a high-value attack surface. For a trust framework device, remote management should use the trust framework itself, not an independent channel that bypasses it.

Phase 4 removes SSH after first boot. Phase 5 (planned) replaces traditional remote management with AT's peer-to-peer, trust-gated, consensus-based fleet management. Software updates are proposed, voted on, and distributed through AT's own encrypted channels. No central server, no SSH keys to manage, no single point of compromise.

During initial provisioning (first boot), busybox provides a minimal shell if physical access is needed. After first boot, the shell is removed from the rootfs overlay.
