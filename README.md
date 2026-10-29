<p align="center">
  <img src="docs/assets/hidder-banner.svg" alt="Hidder — The client companion to ModSeeker. Fabric mod." width="100%">
</p>

<p align="center">
  <a href="https://modrinth.com/mod/hidder"><strong>Modrinth</strong></a> ·
  <a href="https://github.com/RAFIN-G/Hidder/releases"><strong>GitHub releases</strong></a> ·
  <a href="#compatibility">Compatibility</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#what-hidder-sends">What Hidder sends</a> ·
  <a href="#building-from-source">Build from source</a>
</p>

Hidder is the **Fabric client companion** to ModSeeker. It reports your mods and detected launcher when you connect to a ModSeeker server. The server owner decides which mods and launchers are allowed.

<table>
  <tr>
    <td align="center" width="96" style="border: 1px solid #3d444d;">
      <a href="https://modrinth.com/plugin/modseeker"><img src="docs/assets/modseeker.svg" alt="ModSeeker" width="64" height="64"></a>
    </td>
    <td style="border: 1px solid #3d444d;">
      <h3>ModSeeker is required</h3>
      <p>The server needs the <strong>ModSeeker Paper plugin</strong> to use Hidder's reports and enforce its rules. Players install Hidder on their client; server owners install ModSeeker.</p>
      <p><a href="https://modrinth.com/plugin/modseeker"><strong>Get ModSeeker on Modrinth →</strong></a> · <a href="https://github.com/RAFIN-G/ModSeeker">ModSeeker source</a></p>
    </td>
  </tr>
</table>

## Features

| Feature | Description |
| --- | --- |
| **Automatic verification** | Responds to the server's checks when you join, without commands or a separate app. |
| **Report protection** | Signs and encrypts mod reports for the connected server. |
| **Bundled native library** | Includes its Windows library; no separate OpenSSL or C++ runtime installation is needed. |

## Compatibility

**Platform:** Windows x64 · **Mod loader:** Fabric · **Dependency:** Fabric API

Choose a Hidder JAR for your Minecraft version. One JAR supports all three listed Fabric Loader versions.

| Minecraft version | Java | Fabric Loader |
| --- | --- | --- |
| **1.21, 1.21.4, 1.21.7, 1.21.8, 1.21.9, 1.21.10, 1.21.11** | 21 | 0.19.3, 0.19.5, 0.20.1 |
| **26.1.2, 26.2, 26.3** | 25 | 0.19.3, 0.19.5, 0.20.1 |

The download labelled `mc26.1` is for **Minecraft 26.1.2**. Fabric API must also match your Minecraft version. Other Fabric Loader versions are not supported by this release.

## Getting started

1. Create a **Fabric** instance for your Minecraft version using one of the supported Loader versions above.
2. Download the matching [Hidder JAR](https://modrinth.com/mod/hidder/versions) and [Fabric API](https://modrinth.com/mod/fabric-api/versions).
3. Put both files in that instance's `mods/` folder, then launch Minecraft.
4. Join a server running **ModSeeker v3**. Verification happens automatically.

If the server rejects a mod or launcher, follow its disconnect message or contact the server owner.

## What Hidder sends

Reports go to the **Minecraft server you join**, through the existing game connection. Hidder does not use a separate telemetry service.

| Data | When it is sent |
| --- | --- |
| **Mods** | IDs and version strings during mod verification, including entries found in declared bundled mod JARs. |
| **Mod file hashes** | When the server requests advanced verification. These SHA-512 hashes let ModSeeker check approved files. |
| **Launcher** | In response to a launcher challenge. ModSeeker requests this when launcher verification is enabled; the result is a launcher label or `unknown`. |
| **Verification** | Hidder presence, version information, request IDs, signatures and verification errors. |

Hidder reads mod JARs and launcher information locally. It does **not** upload the JAR contents, local file paths or raw process details. It does not report hardware IDs, resource packs or shader packs.

Server administrators can read these reports. ModSeeker logs mod lists to its console by default, and server owners can also enable Discord notifications.

## Building from source

The shared build tool is in [ModSeeker's Tools folder](https://github.com/RAFIN-G/ModSeeker/tree/main/Tools): [StartCustomBuild.ps1](https://github.com/RAFIN-G/ModSeeker/blob/main/Tools/StartCustomBuild.ps1) and its [key generator](https://github.com/RAFIN-G/ModSeeker/blob/main/Tools/ClientReportKeyGenerator.java). Download the full ModSeeker source alongside Hidder and keep those two tool files together.

<details>
<summary>Build ModSeeker and Hidder together</summary>

`StartCustomBuild.ps1` builds **both the ModSeeker server plugin and the Hidder client mod**, including Hidder's native DLL. You need both source repositories, even if you started from only one project's page.

Build on **Windows x64** with **JDK 25** and the following native dependencies:

| Software | What to install |
| --- | --- |
| [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio) | Select **Desktop development with C++**, including the MSVC x64 tools. |
| [Windows SDK](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/) | Install through the Build Tools installer or separately. |
| [OpenSSL 3.x](https://github.com/openssl/openssl) | Provide the headers and x64 static `libcrypto` libraries built with `/MT`. |

The OpenSSL directory must contain `include/openssl/` and `lib/VC/x64/MT/libcrypto_static.lib`. A runtime-only OpenSSL package is not sufficient. To build OpenSSL from source, see its [Windows build instructions](https://github.com/openssl/openssl/blob/master/NOTES-WINDOWS.md); that process also uses [Strawberry Perl](https://strawberryperl.com/) and [NASM](https://www.nasm.us/).

Gradle is included through the wrapper. Git is optional when downloading the source as ZIP files. Players installing the release JARs do not need these build tools.

The default native compiler is MSVC. Optional obfuscated builds require a Windows OLLVM-enabled `clang-cl.exe`, supplied through `-ClangCl`. It must support the obfuscation options in Hidder's native build script; standard LLVM `clang-cl` alone does not provide those passes.

For an OLLVM 16 reference implementation, see [source and build instructions](https://github.com/wwh1004/ollvm-16) or its [compiler downloads](https://github.com/wwh1004/ollvm-16/releases). Obtain or build the compiler separately; it is not bundled with these repositories.

Place the repositories next to each other as `ModSeeker/` and `Hidder/`, then run this from the folder containing both:

```powershell
.\ModSeeker\Tools\StartCustomBuild.ps1
```

On its first run, the tool creates the keys Hidder uses to sign client reports. It builds both projects, checks that ModSeeker recognizes Hidder's key, and saves the JARs in `dist/custom-pair/`. Later builds reuse those keys. The source defaults to Minecraft 26.3 / Java 25.

To initialize the keys without building:

```powershell
.\ModSeeker\Tools\StartCustomBuild.ps1 -InitializeKeysOnly
```

Keep a secure backup of `Hidder/native/client_keys.generated.inc` so future builds can use the same keys. This file contains private key material and must not be published. Each ModSeeker server generates its own separate encryption keys on first startup.

If a dependency is not found automatically, pass its location with `-JdkDirectory`, `-OpenSslDirectory`, `-VcTools` or `-WindowsSdk`. Use the two generated JARs together.

</details>

## Licence

Original Hidder code is licensed under [AGPL-3.0-or-later](LICENSE).

### Third-party licences

- Hidder's DEFLATE reader is adapted from **Mark Adler's puff**, under the [Zlib licence](LICENSES/Zlib.txt). The original notice is retained in [the source](native/mod_inflate.cpp).
- The native library links **OpenSSL 3.x**, under [Apache-2.0](LICENSES/Apache-2.0.txt).
- The **Gradle Wrapper** is distributed under [Apache-2.0](LICENSES/Apache-2.0.txt). Dependency licences remain with their respective projects.
