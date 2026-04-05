# Hidder 📂

Hidder is the **client-side companion** to the [ModSeeker](https://modrinth.com/plugin/modseeker) Paper plugin. Install it on your Fabric client and it handles the rest — reporting your installed mods, detecting your launcher, and proving everything through encrypted, tamper-proof communication that servers can trust.

[![](https://github.com/gabrielvicenteYT/modrinth-icons/raw/main/Branding/Badge/badge-dark.svg)](https://modrinth.com/mod/hidder)

<table>
<tr>
<td align="center" width="50%">
<h3>📦 Mod Reporting</h3>
<p>Collects all installed mods, resource packs, and shaders — encrypted end-to-end before leaving your client</p>
</td>
<td align="center" width="50%">
<h3>🔎 Launcher Detection</h3>
<p>Identifies your launcher using native OS-level inspection — not self-reported, not guessable</p>
</td>
</tr>
</table>

---

## Features

- **Client-Side Only** — Runs exclusively on the client with zero server-side components
- **Native Security Module** — Cryptographic operations run inside a compiled C++ library, not Java bytecode
- **Hybrid Encryption** — Mod list data is encrypted using RSA key exchange + AES-256-CBC
- **Integrity Signatures** — Every response includes a session-bound HMAC proving data authenticity
- **Launcher Detection** — Identifies which launcher started the game using native OS-level APIs
- **Replay Attack Protection** — Cryptographic nonces and timestamps prevent reuse of old responses
- **Automatic Setup** — Native libraries are extracted and loaded at runtime with no manual configuration

## Version Compatibility

---

## Version Compatibility

| Minecraft Version | Fabric Loader | Java | Status |
|-------------------|---------------|------|--------|
| 26.1 / 26.1.1 | 0.18.0+ | Java 25+ | ✅ Latest |
| 1.21.11 | 0.17.2+ | Java 21+ | ✅ Supported |
| 1.21.10 | 0.17.2+ | Java 21+ | ✅ Supported |
| 1.21.9 | 0.17.2+ | Java 21+ | ✅ Supported |
| 1.21.8 | 0.17.2+ | Java 21+ | ✅ Supported |
| 1.21.7 | 0.17.2+ | Java 21+ | ✅ Supported |
| 1.21.4 | 0.17.2+ | Java 21+ | ✅ Supported |

Download the JAR matching your Minecraft version from [Modrinth](https://modrinth.com/mod/hidder) or [Releases](https://github.com/RAFIN-G/Hidder/releases).

---

## Requirements

- **Fabric Loader** 0.17.2 or higher (0.18.0+ for 26.1)
- **Fabric API**
- Java **21+** (Java **25+** for Minecraft 26.1)
- A server running [ModSeeker](https://github.com/RAFIN-G/ModSeeker)

---

## Installation

1. Install **Fabric Loader** for your Minecraft version
2. Download the Hidder JAR matching your version from [Modrinth](https://modrinth.com/mod/hidder) or [Releases](https://github.com/RAFIN-G/Hidder/releases)
3. Place the JAR in your `mods/` folder
4. Launch the game

No configuration is required. Hidder operates silently and responds automatically when a ModSeeker server requests verification.

---

## How It Works

When you join a server running ModSeeker, the following process occurs automatically in the background:

```
Join Server
    |
    v
[ Announce Presence ]       -- Hidder tells the server it's installed
    |
    v
[ Cryptographic Challenge ] -- Server sends a unique challenge
    |                          Hidder signs it using the native security module
    v
[ Launcher Detection ]      -- Native module identifies your launcher
    |                          Result is sent alongside the challenge response
    v
[ Mod List Collection ]     -- Hidder reads your loaded mods from the Fabric runtime
    |                          Encrypts and signs the data
    |                          Sends it to the server
    v
[ Verification Complete ]   -- Server validates everything and admits you ✅
```

The entire process takes less than a second. You will not notice any delay during normal gameplay.

### What Data Is Collected

| Data | Source | Purpose |
|------|--------|---------|
| Installed mods (with versions) | Fabric Loader runtime registry | Blacklist enforcement |
| Resource packs | Game directory scan | Server policy compliance |
| Shader packs | Game directory scan | Server policy compliance |
| Launcher name | Native OS API inspection | Launcher whitelist enforcement |

All collected data is encrypted before transmission and can only be read by the target server.

### Communication Protocol

Hidder communicates with ModSeeker over a custom Minecraft plugin messaging channel:

| Message | Direction | Description |
|---------|-----------|-------------|
| `ANNOUNCE_PRESENCE` | Client > Server | Declares that Hidder is installed |
| `CHALLENGE` | Server > Client | Cryptographic challenge with unique nonce |
| `CHALLENGE_RESPONSE` | Client > Server | Signed response with launcher identification |
| `ACKNOWLEDGE_PRESENCE` | Server > Client | Server confirms the handshake |
| `REQUEST_MODLIST` | Server > Client | Server requests the encrypted mod list |
| `RESPONSE_MODLIST_ENCRYPTED` | Client > Server | Encrypted and integrity-signed mod list |

---

## Security Architecture

Hidder's security is built on three principles: **authentication**, **confidentiality**, and **integrity**.

### Authentication

Every connection uses a unique cryptographic challenge-response handshake. The server generates a random nonce; Hidder signs it using the native security module. This proves the client is running the authentic, unmodified Hidder mod.

### Confidentiality

Mod list data is encrypted using hybrid encryption before transmission. A random AES-256 session key encrypts the payload, and the session key itself is encrypted with the server's RSA public key. Only the target server can decrypt the data.

### Integrity

Each encrypted response includes a session-bound HMAC signature computed inside the native module. The server verifies this signature after decryption, ensuring the data was not modified and was produced during the current session — not replayed from a previous one.

### Native Security Module

Critical operations run inside a compiled C++ library (`hidder_vault.dll`) rather than Java bytecode:

- Cryptographic key operations
- HMAC computation
- Launcher detection via OS APIs
- Data encryption

This significantly raises the difficulty of reverse engineering compared to standard Java-based mods.

> **Warning:** Do not modify, replace, or delete the native library files. Doing so will break communication with ModSeeker servers.

---

## Detected Launchers

Hidder can identify the following launchers through native OS-level inspection:

| Launcher | | Launcher |
|----------|-|----------|
| Prism Launcher | | Lunar Client |
| MultiMC | | Badlion Client |
| CurseForge | | Feather Client |
| Modrinth App | | LabyMod |
| ATLauncher | | TLauncher |
| GDLauncher | | SKLauncher |
| Technic Launcher | | Pojav Launcher |
| FTB App | | |

Unrecognized launchers are reported as `unknown`. Server administrators decide whether to allow or block unknown launchers.

---

## Building from Source

### Prerequisites

- Visual Studio with C++ desktop development tools (Windows native compilation)
- OpenSSL development libraries
- JDK 21+ (JDK 25+ for Minecraft 26.1)
- Gradle (wrapper included)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/RAFIN-G/Hidder
   ```

2. **Key Generation (Required)** 🔑

   Both Hidder and ModSeeker share cryptographic keys. Keys are generated using the tool included in the [ModSeeker repository](https://github.com/RAFIN-G/ModSeeker/tree/main/Tools). You only need to run it once — it generates keys for **both** projects.

   ```bash
   cd ModSeeker/Tools
   javac KeyGen.java
   java KeyGen
   ```

   This generates **5 files**. Each file contains the exact line to find and replace — just open it and follow the instructions inside.

   **2 files go into this repo (Hidder):**

   | Generated File | Destination File | What to Find & Replace |
   |----------------|------------------|------------------------|
   | `CLIENT_KEYS_CPP.txt` | [`native/hidder_vault.cpp`](https://github.com/RAFIN-G/Hidder/blob/main/native/hidder_vault.cpp) | Search for `RSA KEY COMPONENTS` — replace all `const std::string` lines: `B64_MODULUS`, `B64_PUB_EXP`, `B64_PRIV_EXP`, `B64_PRIME1`, `B64_PRIME2`, `B64_EXP1`, `B64_EXP2`, `B64_COEFF`, `SRV_B64_MODULUS`, `SRV_B64_EXP` |
   | `HMAC_SECRET_CPP.txt` | [`native/hidder_vault.cpp`](https://github.com/RAFIN-G/Hidder/blob/main/native/hidder_vault.cpp) | Search for `ENCODED_HMAC_KEY` inside the `computeHmac` function — replace the `unsigned char` array and key length |

   **3 files go into the [ModSeeker](https://github.com/RAFIN-G/ModSeeker) repo:**

   | Generated File | Destination File | Variable to Find |
   |----------------|------------------|------------------|
   | `SERVER_KEY_JAVA.txt` | [`ModSeeker/src/.../SecurityManager.java`](https://github.com/RAFIN-G/ModSeeker/blob/main/src/main/java/com/example/modseeker/SecurityManager.java) | `SERVER_PRIVATE_KEY = "REPLACE_WITH..."` |
   | `SERVER_VERIFY_KEY.txt` | [`ModSeeker/src/.../SecurityManager.java`](https://github.com/RAFIN-G/ModSeeker/blob/main/src/main/java/com/example/modseeker/SecurityManager.java) | `DEFAULT_PUBLIC_KEY = "REPLACE_WITH..."` |
   | `HMAC_SECRET_JAVA.txt` | [`ModSeeker/src/.../HandshakeManager.java`](https://github.com/RAFIN-G/ModSeeker/blob/main/src/main/java/com/example/modseeker/HandshakeManager.java) **AND** [`SecurityManager.java`](https://github.com/RAFIN-G/ModSeeker/blob/main/src/main/java/com/example/modseeker/SecurityManager.java) | `HMAC_SECRET = "REPLACE_WITH..."` (in **both** files — must be identical) |

   > **Important:** Every deployment should use its own unique keys. Never reuse keys from another server. The HMAC secret must be **identical** across `HandshakeManager.java`, `SecurityManager.java`, and `hidder_vault.cpp` — all three files use it for Layer 1 and Layer 3 verification. The HMAC key is XOR-encoded in the C++ source to prevent extraction via `strings` or hex editors on the compiled DLL — it is decoded at runtime and zeroed from memory after use.

3. Compile the native library (Windows):
   ```bash
   native/compile_vault.bat
   ```

4. Build the JAR:
   ```bash
   ./gradlew build    # Linux/macOS
   gradlew.bat build  # Windows
   ```

The compiled JAR will be in `build/libs/`.

### Build Order

When setting up a new deployment from scratch:

1. Run `KeyGen.java` to generate all 5 key files
2. Paste `CLIENT_KEYS_CPP.txt` into `hidder_vault.cpp` → replace the `RSA KEY COMPONENTS` section
3. Paste `HMAC_SECRET_CPP.txt` into `hidder_vault.cpp` → replace the `ENCODED_HMAC_KEY` array
4. Paste `SERVER_KEY_JAVA.txt` and `SERVER_VERIFY_KEY.txt` into `SecurityManager.java`
5. Paste `HMAC_SECRET_JAVA.txt` into **both** `HandshakeManager.java` and `SecurityManager.java`
6. Compile `hidder_vault.dll` (`native/compile_vault.bat`)
7. Build Hidder mod (`gradlew build`)
8. Build ModSeeker plugin (`gradlew jar`)

---

## Technical Summary

| Property | Details |
|----------|---------|
| Mod loader | Fabric |
| Minecraft versions | 1.21.4 – 1.21.11, 26.1 |
| Java version | 21+ (25+ for 26.1) |
| Encryption | RSA-2048 + AES-256-CBC |
| Authentication | HMAC-SHA256 |
| Signatures | RSA-SHA256 |
| Native module | C++ with OpenSSL |
| Platform | Windows (native DLL) |

---

## License

This project is licensed under **AGPL-3.0**. See the [LICENSE](LICENSE) file for details.
