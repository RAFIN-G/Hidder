// SPDX-FileCopyrightText: 2026 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

import java.io.ByteArrayOutputStream;
import java.lang.classfile.ClassFile;
import java.lang.classfile.attribute.CodeAttribute;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.HashSet;
import java.util.Properties;
import java.util.zip.ZipFile;

public final class ClassBytecodeFingerprintGenerator {
    private ClassBytecodeFingerprintGenerator() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 5 || (args.length - 3) % 2 != 0) {
            throw new IllegalArgumentException(
                    "Expected output, runtime identity and source, followed by symbol and class source pairs");
        }
        String runtimeIdentity = args[1];
        if (!runtimeIdentity.matches("mixinextras:[A-Za-z0-9._+\\-]{1,128}")) {
            throw new IllegalArgumentException("Invalid MixinExtras runtime identity");
        }
        byte[] runtimeJar = readSource(args[2]);
        byte[] runtimeDigest = MessageDigest.getInstance("SHA-512").digest(runtimeJar);
        StringBuilder header = new StringBuilder();
        header.append("// SPDX-FileCopyrightText: 2026 ModSeeker\n");
        header.append("// SPDX-License-Identifier: AGPL-3.0-or-later\n\n");
        header.append("static constexpr char EXPECTED_MIXINEXTRAS_ID_VERSION[] = \"")
                .append(runtimeIdentity).append("\";\n");
        appendBytes(header, "EXPECTED_MIXINEXTRAS_SHA512", runtimeDigest);
        for (int index = 3; index < args.length; index += 2) {
            String symbol = args[index];
            if (!symbol.matches("[A-Z][A-Z0-9_]*")) {
                throw new IllegalArgumentException("Invalid fingerprint symbol");
            }
            appendBytes(header, symbol, fingerprint(readSource(args[index + 1])));
        }
        appendLoaderProfiles(header);
        byte[] fingerprintBytes = header.toString().getBytes(StandardCharsets.US_ASCII);
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(fingerprintBytes));
        header.append("static volatile const char CLASS_FINGERPRINT_IDENTITY[65] = \"")
                .append(digest).append("\";\n");
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        byte[] headerBytes = header.toString().getBytes(StandardCharsets.US_ASCII);
        Files.createDirectories(output.getParent());
        Files.write(output, headerBytes,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        Path digestOutput = output.resolveSibling("class_fingerprints.generated.sha256");
        Files.writeString(digestOutput, digest + System.lineSeparator(), StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        Path runtimeOutput = output.resolveSibling("mixinextras-runtime.jar");
        Files.write(runtimeOutput, runtimeJar,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        System.out.println("Generated " + ((args.length - 3) / 2) + " class fingerprints and MixinExtras identity");
    }

    private static void appendLoaderProfiles(StringBuilder header) throws Exception {
        String configuration = System.getProperty("hidder.loaderProfiles");
        if (configuration == null || configuration.isBlank()) {
            throw new IllegalArgumentException("Loader profiles are required");
        }
        Properties profiles = new Properties();
        try (var reader = Files.newBufferedReader(Path.of(configuration), StandardCharsets.UTF_8)) {
            profiles.load(reader);
        }
        String[] versions = required(profiles, "versions").split(",", -1);
        if (versions.length == 0 || versions.length > 16) {
            throw new IllegalArgumentException("Invalid Loader profile count");
        }
        String[] classes = {
                "net/fabricmc/loader/api/FabricLoader.class",
                "net/fabricmc/loader/impl/FabricLoaderImpl.class",
                "net/fabricmc/loader/impl/launch/FabricLauncherBase.class",
                "net/fabricmc/loader/impl/launch/knot/KnotClassLoader.class",
                "net/fabricmc/loader/impl/launch/knot/KnotClassDelegate.class",
                "net/fabricmc/loader/impl/entrypoint/EntrypointStorage.class"
        };
        var seenVersions = new HashSet<String>();
        var seenFingerprints = new HashSet<String>();
        header.append("static constexpr LoaderIntegrityProfile EXPECTED_LOADER_PROFILES[] = {\n");
        for (String version : versions) {
            if (!version.matches("[0-9]+\\.[0-9]+\\.[0-9]+") || !seenVersions.add(version)) {
                throw new IllegalArgumentException("Invalid or duplicate Loader version");
            }
            String jar = required(profiles, version + ".jar");
            if (Files.size(Path.of(jar)) > 16L * 1024 * 1024) {
                throw new IllegalArgumentException("Loader JAR is too large");
            }
            String expected = required(profiles, version + ".sha256");
            String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(readSource(jar)));
            if (!expected.matches("[a-f0-9]{64}") || !actual.equals(expected)) {
                throw new IllegalArgumentException("Loader JAR digest mismatch");
            }
            String runtimeIdentity = required(profiles, version + ".mixinIdentity");
            if (!runtimeIdentity.matches("mixinextras:[A-Za-z0-9._+\\-]{1,128}")) {
                throw new IllegalArgumentException("Invalid MixinExtras identity");
            }
            byte[] runtime = readSource(jar + "!/" + required(profiles, version + ".mixinPath"));
            header.append("    {\"").append(version).append("\", \"").append(runtimeIdentity).append("\", {");
            appendValues(header, MessageDigest.getInstance("SHA-512").digest(runtime));
            header.append("}, {");
            ByteArrayOutputStream measured = new ByteArrayOutputStream();
            for (int index = 0; index < classes.length; index++) {
                byte[] digest = fingerprint(readSource(jar + "!/" + classes[index]));
                measured.write(digest);
                header.append(index == 0 ? "{" : ",{");
                appendValues(header, digest);
                header.append('}');
            }
            if (!seenFingerprints.add(HexFormat.of().formatHex(measured.toByteArray()))) {
                throw new IllegalArgumentException("Ambiguous Loader fingerprints");
            }
            header.append("}},\n");
        }
        header.append("};\n\n");
    }

    private static String required(Properties properties, String key) {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing profile property: " + key);
        return value;
    }

    private static void appendValues(StringBuilder output, byte[] bytes) {
        for (int index = 0; index < bytes.length; index++) {
            if (index > 0) output.append(',');
            output.append(String.format("0x%02x", bytes[index] & 0xff));
        }
    }

    private static void appendBytes(StringBuilder header, String symbol, byte[] bytes) {
        header.append("static constexpr unsigned char ").append(symbol).append('[').append(bytes.length)
                .append("] = {");
        for (int byteIndex = 0; byteIndex < bytes.length; byteIndex++) {
            if (byteIndex > 0) {
                header.append(',');
            }
            if (byteIndex % 8 == 0) {
                header.append("\n    ");
            } else {
                header.append(' ');
            }
            header.append(String.format("0x%02x", bytes[byteIndex] & 0xff));
        }
        header.append("\n};\n\n");
    }

    private static byte[] readSource(String source) throws Exception {
        int separator = source.indexOf("!/");
        if (separator < 0) {
            return Files.readAllBytes(Path.of(source));
        }
        Path archive = Path.of(source.substring(0, separator));
        String entryName = source.substring(separator + 2);
        try (ZipFile zip = new ZipFile(archive.toFile())) {
            var entry = zip.getEntry(entryName);
            if (entry == null || entry.isDirectory()) {
                throw new IllegalArgumentException("Class entry is unavailable");
            }
            try (var input = zip.getInputStream(entry); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                input.transferTo(output);
                return output.toByteArray();
            }
        }
    }

    private static byte[] fingerprint(byte[] classBytes) throws Exception {
        ConstantPoolBytes constantPool = constantPool(classBytes);
        var model = ClassFile.of().parse(classBytes);
        List<MethodBytes> methods = new ArrayList<>();
        for (var method : model.methods()) {
            byte[] code = method.code()
                    .map(value -> ((CodeAttribute) value).codeArray())
                    .orElseGet(() -> new byte[0]);
            methods.add(new MethodBytes(
                    method.methodName().stringValue(),
                    method.methodType().stringValue(),
                    method.flags().flagsMask(),
                    code));
        }
        methods.sort(Comparator.comparing(MethodBytes::name).thenComparing(MethodBytes::descriptor));
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        updateInt(digest, constantPool.count());
        updateBytes(digest, constantPool.bytes());
        updateInt(digest, methods.size());
        for (MethodBytes method : methods) {
            updateBytes(digest, method.name().getBytes(StandardCharsets.UTF_8));
            updateBytes(digest, method.descriptor().getBytes(StandardCharsets.UTF_8));
            updateInt(digest, method.modifiers());
            updateBytes(digest, method.code());
        }
        return digest.digest();
    }

    private static ConstantPoolBytes constantPool(byte[] bytes) {
        if (bytes.length < 10 || ByteBuffer.wrap(bytes, 0, 4).getInt() != 0xCAFEBABE) {
            throw new IllegalArgumentException("Invalid class file");
        }
        int count = readU2(bytes, 8);
        int offset = 10;
        for (int index = 1; index < count; index++) {
            int tag = bytes[offset++] & 0xff;
            switch (tag) {
                case 1 -> {
                    int length = readU2(bytes, offset);
                    offset += 2 + length;
                }
                case 3, 4, 9, 10, 11, 12, 17, 18 -> offset += 4;
                case 5, 6 -> {
                    offset += 8;
                    index++;
                }
                case 7, 8, 16, 19, 20 -> offset += 2;
                case 15 -> offset += 3;
                default -> throw new IllegalArgumentException("Unsupported constant pool tag");
            }
            if (offset > bytes.length) {
                throw new IllegalArgumentException("Truncated class file");
            }
        }
        return new ConstantPoolBytes(count, java.util.Arrays.copyOfRange(bytes, 10, offset));
    }

    private static int readU2(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static void updateBytes(MessageDigest digest, byte[] bytes) {
        updateInt(digest, bytes.length);
        digest.update(bytes);
    }

    private static void updateInt(MessageDigest digest, int value) {
        digest.update(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array());
    }

    private record ConstantPoolBytes(int count, byte[] bytes) {
    }

    private record MethodBytes(String name, String descriptor, int modifiers, byte[] code) {
    }
}
