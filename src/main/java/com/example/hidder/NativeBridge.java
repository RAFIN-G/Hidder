// SPDX-FileCopyrightText: 2025 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

package com.example.hidder;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.ModOrigin;
import java.nio.file.Files;
import java.nio.file.Path;

final class NativeBridge {
    private static volatile boolean loaded;

    private NativeBridge() {
    }

    private static synchronized boolean loadLibrary() {
        if (!loaded) {
            loaded = NativeLibraryLoader.load();
        }
        return loaded;
    }

    static boolean initialize(HidderFabric owner) {
        return validFabricOwner(owner) && loadLibrary() && nativeInitialize(owner);
    }

    static boolean beginConnection(HidderFabric owner, long generation, String connectionContext) {
        return loaded && nativeBeginConnection(owner, generation, connectionContext);
    }

    static void invalidate(HidderFabric owner, long generation) {
        if (loaded) {
            nativeInvalidate(owner, generation);
        }
    }

    static boolean isReady(HidderFabric owner) {
        return loaded && nativeIsReady(owner);
    }

    static String signConnectionChallenge(HidderFabric owner, long generation, String connectionContext,
            String nonce, long timestamp) {
        return loaded
                ? nativeSignConnectionChallenge(owner, generation, connectionContext, nonce, timestamp)
                : "ERROR_STATE";
    }

    static String sealConnectionReport(HidderFabric owner, long generation, String connectionContext,
            String fields, String serverPubKey, String resolvedSources, boolean advanced) {
        return loaded
                ? nativeSealConnectionReport(owner, generation, connectionContext, fields, serverPubKey,
                        resolvedSources, advanced)
                : "ERROR_STATE";
    }

    private static boolean validFabricOwner(HidderFabric owner) {
        try {
            if (owner == null || owner.getClass() != HidderFabric.class
                    || owner.getClass().getClassLoader() != NativeBridge.class.getClassLoader()) {
                return false;
            }
            FabricLoader loader = FabricLoader.getInstance();
            if (!loader.isModLoaded(HidderFabric.MOD_ID)) {
                return false;
            }
            boolean registered = loader.getEntrypoints("client", ClientModInitializer.class).stream()
                    .anyMatch(entrypoint -> entrypoint == owner);
            if (!registered) {
                return false;
            }
            ModContainer container = loader.getModContainer(HidderFabric.MOD_ID).orElseThrow();
            if (!HidderFabric.MOD_ID.equals(container.getMetadata().getId())
                    || container.getOrigin().getKind() != ModOrigin.Kind.PATH) {
                return false;
            }
            if (NativeBridge.class.getProtectionDomain() == null
                    || NativeBridge.class.getProtectionDomain().getCodeSource() == null) {
                return false;
            }
            Path codeSource = Path.of(NativeBridge.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                    .toAbsolutePath().normalize();
            for (Path origin : container.getOrigin().getPaths()) {
                Path normalized = origin.toAbsolutePath().normalize();
                if (codeSource.equals(normalized)
                        || Files.exists(codeSource) && Files.exists(normalized) && Files.isSameFile(codeSource, normalized)) {
                    return true;
                }
            }
            return false;
        } catch (Exception exception) {
            return false;
        }
    }

    static boolean isLoaded() {
        return loaded;
    }

    private static native boolean nativeInitialize(HidderFabric owner);

    private static native boolean nativeBeginConnection(HidderFabric owner, long generation,
            String connectionContext);

    private static native void nativeInvalidate(HidderFabric owner, long generation);

    private static native boolean nativeIsReady(HidderFabric owner);

    private static native String nativeSignConnectionChallenge(HidderFabric owner, long generation,
            String connectionContext, String nonce, long timestamp);

    private static native String nativeSealConnectionReport(HidderFabric owner, long generation,
            String connectionContext, String fields, String serverPubKey, String resolvedSources, boolean advanced);
}
