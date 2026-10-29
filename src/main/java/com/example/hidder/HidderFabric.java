// SPDX-FileCopyrightText: 2025 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

package com.example.hidder;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.ModOrigin;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.charset.StandardCharsets;
import java.util.TreeMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class HidderFabric implements ClientModInitializer {
    public static final String MOD_ID = "hidder";
    private static final String VERSION = BuildTarget.MINECRAFT_VERSION;
    private static final String PROTOCOL_VERSION = "3.6";
    private static final CustomPacketPayload.Type<ModSeekerPayload> MODSEEKER_TYPE = NetworkCompatibility.createType();
    private static final Logger LOGGER = LoggerFactory.getLogger("Hidder");
    private static final int MAX_MESSAGE_BYTES = 32767;
    private final ThreadPoolExecutor sealExecutor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(1), task -> {
                Thread thread = new Thread(task, "Hidder-Seal");
                thread.setDaemon(true);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());
    private volatile long connectionGeneration;
    private volatile String connectionContext = "";
    private boolean requestInFlight;

    @Override
    public void onInitializeClient() {
        if (!NativeBridge.initialize(this)) {
            LOGGER.error("[Hidder] Native lifecycle initialization failed");
        }
        NetworkCompatibility.register(ModSeekerPayload.CODEC);

        ClientPlayNetworking.registerGlobalReceiver(ModSeekerPayload.TYPE, (payload, context) -> {
            String message = new String(payload.data(), StandardCharsets.UTF_8);
            context.client().execute(() -> processServerMessage(message, context));
        });

        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            client.execute(() -> {
                long generation = ++connectionGeneration;
                connectionContext = connectionIdentity(handler);
                requestInFlight = false;
                if (!NativeBridge.beginConnection(this, generation, connectionContext)) {
                    LOGGER.error("[Hidder] Native connection lifecycle rejected initialization");
                }
                announcePresenceToServer(sender);
            });
        });
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            client.execute(() -> {
                long generation = ++connectionGeneration;
                NativeBridge.invalidate(this, generation);
                connectionContext = "";
                requestInFlight = false;
            });
        });
    }

    private void processServerMessage(String message, ClientPlayNetworking.Context context) {
        try {
            JsonObject json = JsonParser.parseString(message).getAsJsonObject();
            String type = json.get("messageType").getAsString();
            switch (type) {
                case "REQUEST_MODLIST" -> sendModListResponse(context,
                        json.get("checkId").getAsString(),
                        json.get("nonce").getAsString(),
                        json.get("serverPubKey").getAsString(),
                        json.get("advanced").getAsBoolean());
                case "CHALLENGE" -> handleChallenge(json, context);
                case "ACKNOWLEDGE_PRESENCE" -> { }
                default -> { }
            }
        } catch (Exception ignored) {
        }
    }

    private void handleChallenge(JsonObject message, ClientPlayNetworking.Context context) {
        try {
            String nonce = message.get("nonce").getAsString();
            long timestamp = message.get("timestamp").getAsLong();

            String signature;
            String launcherId;

            if (NativeBridge.isReady(this)) {
                String signedResponse = NativeBridge.signConnectionChallenge(this, connectionGeneration,
                        connectionContext, nonce, timestamp);
                int separator = signedResponse == null ? -1 : signedResponse.indexOf('|');
                if (separator > 0 && separator < signedResponse.length() - 1) {
                    launcherId = signedResponse.substring(0, separator);
                    signature = signedResponse.substring(separator + 1);
                } else {
                    launcherId = "unknown";
                    signature = signedResponse == null ? "ERROR_SIGN" : signedResponse;
                }
            } else {
                signature = "DLL_NOT_LOADED";
                launcherId = "unknown";
            }

            JsonObject response = new JsonObject();
            response.addProperty("messageType", "CHALLENGE_RESPONSE");
            response.addProperty("signature", signature);
            response.addProperty("launcherId", launcherId);

            sendPluginMessage(response.toString(), context.responseSender());

        } catch (Exception | LinkageError failure) {
            long generation = ++connectionGeneration;
            NativeBridge.invalidate(this, generation);
            try {
                JsonObject errorResponse = new JsonObject();
                errorResponse.addProperty("messageType", "CHALLENGE_RESPONSE");
                errorResponse.addProperty("signature", "CLIENT_ERROR");
                errorResponse.addProperty("launcherId", "unknown");
                sendPluginMessage(errorResponse.toString(), context.responseSender());
            } catch (Exception ignored) {
            }
        }
    }

    private void announcePresenceToServer(PacketSender sender) {
        try {
            String announceJson = "{\"messageType\":\"ANNOUNCE_PRESENCE\",\"modId\":\"hidder\",\"version\":\"" + VERSION + "\",\"protocol\":\"" + PROTOCOL_VERSION + "\",\"capabilities\":[\"modlist_request\"]}";
            sendPluginMessage(announceJson, sender);
        } catch (Exception ignored) {
        }
    }

    private void sendModListResponse(ClientPlayNetworking.Context context, String checkId, String nonce, String pubKey,
            boolean advanced) {
        final var client = context.client();
        if (requestInFlight) {
            return;
        }
        requestInFlight = true;
        long generation = connectionGeneration;
        String activeConnection = connectionContext;
        try {
            sealExecutor.execute(() -> {
                String response = null;
                try {
                    if (generation == connectionGeneration) {
                        response = generateSystemInfoResponse(generation, activeConnection, checkId, nonce, pubKey,
                                advanced);
                    }
                } catch (Exception | LinkageError failure) {
                    response = errorEnvelope("JAVA_EXCEPTION");
                }
                String completedResponse = response;
                client.execute(() -> {
                    if (generation != connectionGeneration) {
                        return;
                    }
                    requestInFlight = false;
                    if (completedResponse != null) sendViaClientConnection(completedResponse);
                });
            });
        } catch (RejectedExecutionException e) {
            requestInFlight = false;
            sendViaClientConnection(errorEnvelope("WORKER_BUSY"));
        }
    }

    private void sendViaClientConnection(String message) {
        try {
            ClientPlayNetworking.send(new ModSeekerPayload(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ignored) {
        }
    }

    private void sendPluginMessage(String message, PacketSender sender) {
        try {
            sender.sendPacket(new ModSeekerPayload(message.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ignored) {
        }
    }

    private String generateSystemInfoResponse(long generation, String activeConnection, String checkId, String nonce,
            String pubKey, boolean advanced) {
        try {
            StringBuilder fields = new StringBuilder();
            fields.append("checkId=").append(checkId);
            fields.append("|").append("nonce=").append(nonce != null ? nonce : "none");

            String encryptedData = "";
            String errorCode = "";

            if (!NativeBridge.isReady(this)) {
                errorCode = "DLL_NOT_LOADED";
            } else if (pubKey == null || pubKey.isEmpty()) {
                errorCode = "NO_SERVER_KEY";
            } else {
                String sources = loaderSources();
                encryptedData = NativeBridge.sealConnectionReport(this, generation, activeConnection,
                        fields.toString(), pubKey, sources, advanced);
                if (encryptedData == null || encryptedData.isEmpty()) {
                    errorCode = "NATIVE_RETURNED_EMPTY";
                } else if (encryptedData.startsWith("ERROR_")) {
                    errorCode = "NATIVE_" + encryptedData;
                    encryptedData = "";
                } else if (!encryptedData.contains("|")) {
                    errorCode = "NATIVE_INVALID_FORMAT";
                    encryptedData = "";
                }
            }

            String envelope = "{\"messageType\":\"RESPONSE_MODLIST_ENCRYPTED\",\"modId\":\"" + MOD_ID
                    + "\",\"version\":\"" + VERSION + "\",\"ciphertext\":\"%s\"}";
            String response = envelope.formatted(errorCode.isEmpty() ? encryptedData : errorCode);
            return response.length() <= MAX_MESSAGE_BYTES ? response : envelope.formatted("REPORT_TOO_LARGE");
        } catch (Exception | LinkageError failure) {
            return errorEnvelope("JAVA_EXCEPTION");
        }
    }

    private String errorEnvelope(String code) {
        return "{\"messageType\":\"RESPONSE_MODLIST_ENCRYPTED\",\"ciphertext\":\"" + code + "\"}";
    }

    private String connectionIdentity(net.minecraft.client.multiplayer.ClientPacketListener handler) {
        if (handler == null || handler.getConnection() == null || handler.getConnection().getRemoteAddress() == null) {
            return "";
        }
        return handler.getConnection().getRemoteAddress().toString();
    }

    private String loaderSources() {
        TreeMap<String, String> sources = new TreeMap<>();
        for (ModContainer mod : FabricLoader.getInstance().getAllMods()) {
            if ("builtin".equals(mod.getMetadata().getType())) {
                continue;
            }
            ModContainer source = mod;
            int depth = 0;
            while (source.getOrigin().getKind() == ModOrigin.Kind.NESTED) {
                if (++depth > 8) {
                    throw new IllegalStateException("Fabric mod nesting is too deep");
                }
                source = source.getContainingMod()
                        .orElseThrow(() -> new IllegalStateException("Nested Fabric mod has no parent"));
            }
            ModOrigin origin = source.getOrigin();
            if (origin.getKind() != ModOrigin.Kind.PATH || origin.getPaths().size() != 1
                    || !origin.getPaths().getFirst().toString().endsWith(".jar")) {
                throw new IllegalStateException("Unsupported Fabric mod origin for " + mod.getMetadata().getId());
            }
            sources.put(mod.getMetadata().getId(),
                    origin.getPaths().getFirst().toAbsolutePath().normalize().toString());
        }
        StringBuilder result = new StringBuilder();
        for (var entry : sources.entrySet()) {
            if (!result.isEmpty()) result.append('\n');
            result.append(entry.getKey()).append('\t').append(entry.getValue());
        }
        return result.toString();
    }

    public record ModSeekerPayload(byte[] data) implements CustomPacketPayload {
        public static final Type<ModSeekerPayload> TYPE = MODSEEKER_TYPE;
        public static final StreamCodec<RegistryFriendlyByteBuf, ModSeekerPayload> CODEC = StreamCodec.of(
                (buf, value) -> buf.writeBytes(value.data),
                buf -> {
                    int length = buf.readableBytes();
                    if (length > MAX_MESSAGE_BYTES) {
                        throw new IllegalArgumentException("ModSeeker payload too large");
                    }
                    byte[] data = new byte[length];
                    buf.readBytes(data);
                    return new ModSeekerPayload(data);
                });

        @Override
        public Type<? extends CustomPacketPayload> type() {
            return TYPE;
        }
    }
}
