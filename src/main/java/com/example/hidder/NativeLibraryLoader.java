// SPDX-FileCopyrightText: 2026 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

package com.example.hidder;

import com.sun.nio.file.ExtendedOpenOption;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.UserPrincipal;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

final class NativeLibraryLoader {
    private static final String VAULT_NAME = "hidder_vault.dll";
    private static final String DIGEST_NAME = "native-digests.properties";
    private static final String MARKER_NAME = "cleanup.marker";
    private static final Set<String> EXTRACTION_NAMES = Set.of(VAULT_NAME, MARKER_NAME);
    private static final Set<String> EXPECTED_MANIFEST_KEYS = Set.of(
            VAULT_NAME + ".sha256",
            VAULT_NAME + ".size");
    private static final long MAX_NATIVE_BYTES = 16L * 1024 * 1024;
    private static final int MAX_MANIFEST_BYTES = 4096;
    private static final Duration EXTRACTION_LIMIT = Duration.ofSeconds(15);
    private static volatile Extraction activeExtraction;

    private NativeLibraryLoader() {
    }

    static synchronized boolean load() {
        if (activeExtraction != null) {
            return true;
        }
        Extraction extraction = null;
        try {
            long deadline = System.nanoTime() + EXTRACTION_LIMIT.toNanos();
            TempRoot root = trustedTempRoot();
            PackageData packaged = readPackage(deadline);
            extraction = extract(packaged, root, deadline);
            verifyExtraction(extraction, deadline);
            System.load(extraction.vault().path().toString());
            verifyExtraction(extraction, deadline);
            pruneStaleDirectories(root, extraction.directory(), deadline);
            activeExtraction = extraction;
            installCleanup(extraction);
            return true;
        } catch (Exception | LinkageError exception) {
            cleanup(extraction);
            System.err.println("Failed to load Native Vault: " + exception.getClass().getSimpleName());
            return false;
        }
    }

    private static PackageData readPackage(long deadline) throws Exception {
        CodeSource source = NativeBridge.class.getProtectionDomain() == null
                ? null : NativeBridge.class.getProtectionDomain().getCodeSource();
        if (source == null || source.getLocation() == null
                || !"file".equalsIgnoreCase(source.getLocation().getProtocol())) {
            throw new IOException("Native code source is unavailable");
        }
        URI location = source.getLocation().toURI();
        Path codeSource = Path.of(location).toAbsolutePath().normalize();
        BasicFileAttributes attributes = Files.readAttributes(codeSource, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (attributes.isRegularFile() && !attributes.isSymbolicLink() && !attributes.isOther()) {
            return readJar(codeSource, deadline);
        }
        if (attributes.isDirectory() && !attributes.isSymbolicLink() && !attributes.isOther()) {
            return readDevelopmentDirectory(codeSource, deadline);
        }
        throw new IOException("Native code source type is invalid");
    }

    private static PackageData readJar(Path jarPath, long deadline) throws Exception {
        try (JarFile jar = new JarFile(jarPath.toFile(), false)) {
            int vaultCount = 0;
            int digestCount = 0;
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                if (VAULT_NAME.equals(name)) {
                    vaultCount++;
                } else if (DIGEST_NAME.equals(name)) {
                    digestCount++;
                } else if (!name.contains("/") && name.toLowerCase(Locale.ROOT).endsWith(".dll")) {
                    throw new IOException("Unexpected native resource");
                }
            }
            if (vaultCount != 1 || digestCount != 1) {
                throw new IOException("Native resource count is invalid");
            }
            byte[] manifestBytes = readBounded(jar.getInputStream(jar.getJarEntry(DIGEST_NAME)),
                    MAX_MANIFEST_BYTES, deadline);
            NativeManifest manifest = parseManifest(manifestBytes);
            JarEntry vaultEntry = jar.getJarEntry(VAULT_NAME);
            if (vaultEntry.getSize() != manifest.size()) {
                throw new IOException("Native resource size metadata is invalid");
            }
            byte[] vault = readBounded(jar.getInputStream(vaultEntry), manifest.size(), deadline);
            verifyBytes(vault, manifest);
            return new PackageData(vault, manifest);
        }
    }

    private static PackageData readDevelopmentDirectory(Path classesDirectory, long deadline) throws Exception {
        Path suffix = Path.of("build", "classes", "java", "main");
        if (!classesDirectory.endsWith(suffix)) {
            throw new IOException("Development code source is invalid");
        }
        Path projectDirectory = classesDirectory;
        for (int index = 0; index < suffix.getNameCount(); index++) {
            projectDirectory = projectDirectory.getParent();
        }
        if (projectDirectory == null) {
            throw new IOException("Development project directory is invalid");
        }
        Path resourceDirectory = projectDirectory.resolve(Path.of("build", "resources", "main"))
                .toAbsolutePath().normalize();
        requireDirectory(resourceDirectory);
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(resourceDirectory, "*.dll")) {
            for (Path path : stream) {
                if (!VAULT_NAME.equals(path.getFileName().toString())) {
                    throw new IOException("Unexpected development native resource");
                }
            }
        }
        byte[] manifestBytes = readRegularFile(resourceDirectory.resolve(DIGEST_NAME), MAX_MANIFEST_BYTES, deadline);
        NativeManifest manifest = parseManifest(manifestBytes);
        byte[] vault = readRegularFile(resourceDirectory.resolve(VAULT_NAME), manifest.size(), deadline);
        verifyBytes(vault, manifest);
        return new PackageData(vault, manifest);
    }

    private static NativeManifest parseManifest(byte[] bytes) throws IOException {
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(bytes));
        if (!properties.stringPropertyNames().equals(EXPECTED_MANIFEST_KEYS)) {
            throw new IOException("Native digest manifest keys are invalid");
        }
        String digestText = properties.getProperty(VAULT_NAME + ".sha256");
        String sizeText = properties.getProperty(VAULT_NAME + ".size");
        if (digestText == null || !digestText.matches("[0-9a-f]{64}")) {
            throw new IOException("Native digest metadata is invalid");
        }
        long size;
        try {
            size = Long.parseLong(sizeText);
        } catch (RuntimeException exception) {
            throw new IOException("Native size metadata is invalid", exception);
        }
        if (size <= 0 || size > MAX_NATIVE_BYTES) {
            throw new IOException("Native size metadata is out of bounds");
        }
        return new NativeManifest(size, HexFormat.of().parseHex(digestText));
    }

    private static byte[] readRegularFile(Path path, long maximum, long deadline) throws IOException {
        BasicFileAttributes before = requireRegularFile(path);
        if (before.size() > maximum) {
            throw new IOException("Native resource exceeds its bound");
        }
        byte[] bytes;
        try (InputStream input = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            bytes = readBounded(input, maximum, deadline);
        }
        BasicFileAttributes after = requireRegularFile(path);
        if (before.size() != after.size() || before.lastModifiedTime().compareTo(after.lastModifiedTime()) != 0) {
            throw new IOException("Native resource changed while reading");
        }
        return bytes;
    }

    private static byte[] readBounded(InputStream input, long maximum, long deadline) throws IOException {
        if (input == null || maximum < 0 || maximum > MAX_NATIVE_BYTES) {
            throw new IOException("Native resource is unavailable");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream((int) Math.min(maximum, 64 * 1024));
        byte[] buffer = new byte[8192];
        long total = 0;
        while (true) {
            checkDeadline(deadline);
            int read = input.read(buffer);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                continue;
            }
            total += read;
            if (total > maximum) {
                throw new IOException("Native resource exceeds its bound");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static TempRoot trustedTempRoot() throws IOException {
        String configured = System.getProperty("java.io.tmpdir");
        String userName = System.getProperty("user.name");
        if (configured == null || configured.isBlank() || userName == null || userName.isBlank()) {
            throw new IOException("Native extraction environment is invalid");
        }
        Path root = Path.of(configured).toAbsolutePath().normalize().toRealPath();
        if (!root.getFileSystem().equals(FileSystems.getDefault())
                || root.toString().startsWith("\\\\")) {
            throw new IOException("Native extraction root is invalid");
        }
        requireDirectory(root);
        UserPrincipal user = root.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(userName);
        if (!Files.getOwner(root, LinkOption.NOFOLLOW_LINKS).equals(user)) {
            throw new IOException("Native extraction root owner is invalid");
        }
        if (Files.getFileAttributeView(root, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) == null) {
            throw new IOException("Native extraction root ACL is unavailable");
        }
        return new TempRoot(root, user);
    }

    private static Extraction extract(PackageData packaged, TempRoot root, long deadline) throws Exception {
        Path directory = Files.createTempDirectory(root.path(), "hidder-native-", ownerAcl(root.owner()));
        NativeFile vault = null;
        Path marker = null;
        try {
            verifyDirectory(directory, root.owner());
            vault = createNativeFile(directory.resolve(VAULT_NAME), packaged.vault(), packaged.manifest(),
                    root.owner(), deadline);
            marker = createMarker(directory, packaged.manifest(), root.owner(), deadline);
            Extraction extraction = new Extraction(directory, root.owner(), vault, marker);
            verifyExtraction(extraction, deadline);
            return extraction;
        } catch (Throwable exception) {
            cleanup(new Extraction(directory, root.owner(), vault, marker));
            throw exception;
        }
    }

    private static Path createMarker(Path directory, NativeManifest manifest, UserPrincipal owner, long deadline)
            throws Exception {
        Path marker = directory.resolve(MARKER_NAME);
        Files.createFile(marker, ownerAcl(owner));
        byte[] bytes = manifestBytes(manifest);
        try (FileChannel channel = FileChannel.open(marker, Set.of(
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
                ExtendedOpenOption.NOSHARE_WRITE,
                ExtendedOpenOption.NOSHARE_DELETE))) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
        verifyMarker(marker, manifest, owner, deadline);
        return marker;
    }

    private static NativeFile createNativeFile(Path path, byte[] bytes, NativeManifest manifest,
            UserPrincipal owner, long deadline) throws Exception {
        Set<OpenOption> options = Set.of(
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
                ExtendedOpenOption.NOSHARE_WRITE,
                ExtendedOpenOption.NOSHARE_DELETE);
        FileChannel writer = null;
        FileChannel channel = null;
        try {
            Files.createFile(path, ownerAcl(owner));
            writer = FileChannel.open(path, options);
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                checkDeadline(deadline);
                writer.write(buffer);
            }
            writer.force(true);
            writer.close();
            writer = null;
            channel = FileChannel.open(path, Set.of(
                    StandardOpenOption.READ,
                    LinkOption.NOFOLLOW_LINKS,
                    ExtendedOpenOption.NOSHARE_WRITE,
                    ExtendedOpenOption.NOSHARE_DELETE));
            NativeFile file = new NativeFile(path.toAbsolutePath().normalize(), channel, manifest);
            verifyNativeFile(file, owner, deadline);
            return file;
        } catch (Throwable exception) {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException ignored) {
                }
            }
            if (channel != null) {
                try {
                    channel.close();
                } catch (IOException ignored) {
                }
            }
            throw exception;
        }
    }

    private static void verifyExtraction(Extraction extraction, long deadline) throws Exception {
        if (extraction == null || extraction.vault() == null) {
            throw new IOException("Native extraction is incomplete");
        }
        verifyDirectory(extraction.directory(), extraction.owner());
        verifyNativeFile(extraction.vault(), extraction.owner(), deadline);
        verifyMarker(extraction.marker(), extraction.vault().manifest(), extraction.owner(), deadline);
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(extraction.directory())) {
            int count = 0;
            for (Path path : stream) {
                count++;
                if (!EXTRACTION_NAMES.contains(path.getFileName().toString())) {
                    throw new IOException("Native extraction contains an unexpected file");
                }
            }
            if (count != EXTRACTION_NAMES.size()) {
                throw new IOException("Native extraction file count is invalid");
            }
        }
        verifyDirectory(extraction.directory(), extraction.owner());
    }

    private static void verifyNativeFile(NativeFile file, UserPrincipal owner, long deadline) throws Exception {
        BasicFileAttributes attributes = requireRegularFile(file.path());
        if (attributes.size() != file.manifest().size()) {
            throw new IOException("Extracted native size is invalid");
        }
        verifyOwnerAcl(file.path(), owner);
        byte[] actual = digest(file.channel(), file.manifest().size(), deadline);
        if (!MessageDigest.isEqual(actual, file.manifest().digest())) {
            throw new IOException("Extracted native digest is invalid");
        }
        requireRegularFile(file.path());
    }

    private static void verifyMarker(Path marker, NativeManifest manifest, UserPrincipal owner, long deadline)
            throws Exception {
        verifyOwnerAcl(marker, owner);
        byte[] actual = readRegularFile(marker, MAX_MANIFEST_BYTES, deadline);
        if (!MessageDigest.isEqual(actual, manifestBytes(manifest))) {
            throw new IOException("Native cleanup marker is invalid");
        }
    }

    private static byte[] manifestBytes(NativeManifest manifest) {
        String text = VAULT_NAME + ".sha256=" + HexFormat.of().formatHex(manifest.digest()) + "\n"
                + VAULT_NAME + ".size=" + manifest.size() + "\n";
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] digest(FileChannel channel, long expectedSize, long deadline) throws Exception {
        MessageDigest digest = sha256();
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        channel.position(0);
        long total = 0;
        while (true) {
            checkDeadline(deadline);
            int read = channel.read(buffer);
            if (read < 0) {
                break;
            }
            if (read == 0) {
                continue;
            }
            total += read;
            if (total > expectedSize) {
                throw new IOException("Extracted native exceeds its bound");
            }
            buffer.flip();
            digest.update(buffer);
            buffer.clear();
        }
        if (total != expectedSize) {
            throw new IOException("Extracted native length is invalid");
        }
        channel.position(0);
        return digest.digest();
    }

    private static void verifyBytes(byte[] bytes, NativeManifest manifest) throws Exception {
        if (bytes.length != manifest.size()
                || !MessageDigest.isEqual(sha256().digest(bytes), manifest.digest())) {
            throw new IOException("Packaged native digest is invalid");
        }
    }

    private static BasicFileAttributes requireDirectory(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new IOException("Native directory type is invalid");
        }
        return attributes;
    }

    private static BasicFileAttributes requireRegularFile(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.isOther()) {
            throw new IOException("Native file type is invalid");
        }
        return attributes;
    }

    private static void verifyDirectory(Path path, UserPrincipal owner) throws IOException {
        requireDirectory(path);
        if (!path.toAbsolutePath().normalize().equals(path.toRealPath(LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("Native directory path is unstable");
        }
        verifyOwnerAcl(path, owner);
    }

    private static void verifyOwnerAcl(Path path, UserPrincipal owner) throws IOException {
        if (!Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(owner)) {
            throw new IOException("Native path owner is invalid");
        }
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("Native path ACL is unavailable");
        }
        List<AclEntry> acl = view.getAcl();
        if (acl.size() != 1 || acl.get(0).type() != AclEntryType.ALLOW
                || !acl.get(0).principal().equals(owner)
                || !acl.get(0).permissions().containsAll(EnumSet.allOf(AclEntryPermission.class))) {
            throw new IOException("Native path ACL is not owner-only");
        }
    }

    private static FileAttribute<List<AclEntry>> ownerAcl(UserPrincipal owner) {
        AclEntry entry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .setFlags(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT)
                .build();
        return new FileAttribute<>() {
            @Override
            public String name() {
                return "acl:acl";
            }

            @Override
            public List<AclEntry> value() {
                return List.of(entry);
            }
        };
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static void checkDeadline(long deadline) throws IOException {
        if (System.nanoTime() - deadline > 0) {
            throw new IOException("Native extraction exceeded its deadline");
        }
    }

    private static void installCleanup(Extraction extraction) {
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> cleanup(extraction), "Hidder-Native-Cleanup"));
        } catch (IllegalStateException | SecurityException ignored) {
        }
    }

    private static void cleanup(Extraction extraction) {
        if (extraction == null) {
            return;
        }
        NativeFile vault = extraction.vault();
        if (vault != null) {
            try {
                vault.channel().close();
            } catch (IOException ignored) {
            }
        }
    }

    private static void pruneStaleDirectories(TempRoot root, Path activeDirectory, long deadline) {
        int inspected = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(root.path(), "hidder-native-*")) {
            for (Path directory : stream) {
                if (++inspected > 128) {
                    return;
                }
                checkDeadline(deadline);
                if (!directory.toAbsolutePath().normalize().equals(activeDirectory)) {
                    pruneStaleDirectory(root.path(), directory, root.owner(), deadline);
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void pruneStaleDirectory(Path root, Path directory, UserPrincipal owner, long deadline) {
        try {
            verifyDirectory(directory, owner);
            Set<String> names = new java.util.HashSet<>();
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
                for (Path path : stream) {
                    names.add(path.getFileName().toString());
                }
            }
            if (!names.equals(EXTRACTION_NAMES)) {
                return;
            }
            Path marker = directory.resolve(MARKER_NAME);
            verifyOwnerAcl(marker, owner);
            NativeManifest manifest = parseManifest(readRegularFile(marker, MAX_MANIFEST_BYTES, deadline));
            Path vault = directory.resolve(VAULT_NAME);
            verifyOwnerAcl(vault, owner);
            nativePruneStaleExtraction(root.toString(), directory.toAbsolutePath().normalize().toString(),
                    manifest.size(), manifest.digest());
        } catch (Exception ignored) {
        }
    }

    private static native boolean nativePruneStaleExtraction(String root, String directory, long size, byte[] digest);

    private record NativeManifest(long size, byte[] digest) {
        private NativeManifest {
            digest = Arrays.copyOf(digest, digest.length);
        }

        @Override
        public byte[] digest() {
            return Arrays.copyOf(digest, digest.length);
        }
    }

    private record PackageData(byte[] vault, NativeManifest manifest) {
        private PackageData {
            vault = Arrays.copyOf(vault, vault.length);
        }

        @Override
        public byte[] vault() {
            return Arrays.copyOf(vault, vault.length);
        }
    }

    private record TempRoot(Path path, UserPrincipal owner) {
    }

    private record NativeFile(Path path, FileChannel channel, NativeManifest manifest) {
    }

    private record Extraction(Path directory, UserPrincipal owner, NativeFile vault, Path marker) {
    }
}
