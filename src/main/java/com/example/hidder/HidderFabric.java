/*
 * Copyright (C) 2025 ModSeeker
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.example.hidder;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;
import io.netty.buffer.Unpooled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class HidderFabric implements ClientModInitializer {
    public static final String MOD_ID = "hidder";
    private static final String VERSION = "26.1";
    private static final Identifier MODSEEKER_IDENTIFIER = Identifier.parse("modseeker:modlist");
    private static final Logger LOGGER = LoggerFactory.getLogger("Hidder");
    private static final boolean DEBUG_MODE = false;

    // Layer 3 nonce received from REQUEST_MODLIST (per-session)
    private String layer3Nonce = null;

    @Override
    public void onInitializeClient() {
        PayloadTypeRegistry.serverboundPlay().register(ModSeekerPayload.ID, ModSeekerPayload.CODEC);
        PayloadTypeRegistry.clientboundPlay().register(ModSeekerPayload.ID, ModSeekerPayload.CODEC);

        ClientPlayNetworking.registerGlobalReceiver(ModSeekerPayload.ID, (payload, context) -> {
            String message = extractStringFromPacket(payload.data());
            context.client().execute(() -> processServerMessage(message, context));
        });

        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            client.execute(() -> announcePresenceToServer(sender));
        });

        // Initialize packet signer

        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            // Connection disconnected
        });
    }

    private String extractStringFromPacket(FriendlyByteBuf buf) {
        try {
            byte[] bytes = new byte[buf.readableBytes()];
            buf.readBytes(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private void processServerMessage(String message, ClientPlayNetworking.Context context) {
        try {
            if (message.contains("REQUEST_MODLIST")) {
                LOGGER.info("[Hidder] Processing: REQUEST_MODLIST");
                int start;
                int end;
                String checkId = "unknown";
                if (message.contains("\"checkId\":\"")
                        && (end = message.indexOf("\"", start = message.indexOf("\"checkId\":\"") + 11)) > start) {
                    checkId = message.substring(start, end);
                }
                // Extract Layer 3 nonce from REQUEST_MODLIST
                String nonce = extractJsonValue(message, "nonce");
                if (nonce != null && !nonce.isEmpty()) {
                    this.layer3Nonce = nonce;
                    LOGGER.info("[Hidder] Layer 3 nonce received");
                }
                sendModListResponse(context, checkId);
            } else if (message.contains("\"messageType\":\"CHALLENGE\"")) {
                LOGGER.info("[Hidder] Processing: CHALLENGE");
                handleChallenge(message, context);
            } else if (message.contains("ACKNOWLEDGE_PRESENCE")) {
                LOGGER.info("[Hidder] Processing: ACKNOWLEDGE_PRESENCE");
            } else {
                LOGGER.info("[Hidder] Processing: UNKNOWN message type: " + message.substring(0, Math.min(message.length(), 80)));
            }
        } catch (Exception e) {
            LOGGER.error("[Hidder] ERROR in processServerMessage: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleChallenge(String message, ClientPlayNetworking.Context context) {
        try {
            String nonce = extractJsonValue(message, "nonce");
            String timestampStr = extractJsonValue(message, "timestamp");
            long timestamp = Long.parseLong(timestampStr);

            String hmac;
            String launcherId;
            String launcherName;

            if (NativeBridge.isLoaded()) {
                String dataToSign = nonce + timestamp;
                hmac = NativeBridge.computeHmac(dataToSign);
                launcherId = NativeBridge.detectLauncher();
                launcherName = getLauncherDisplayName(launcherId);
            } else {
                hmac = "DLL_NOT_LOADED";
                launcherId = "unknown";
                launcherName = "Unknown (Native Error)";
            }

            String response = "{\"messageType\":\"CHALLENGE_RESPONSE\"," +
                    "\"hmac\":\"" + hmac + "\"," +
                    "\"launcherId\":\"" + launcherId + "\"," +
                    "\"launcherName\":\"" + launcherName + "\"}";

            sendPluginMessage(response, context.responseSender());

        } catch (Throwable t) {
            LOGGER.error("[Hidder] CRITICAL ERROR in handleChallenge: " + t.getClass().getName() + " - " + t.getMessage());
            t.printStackTrace();
            try {
                String errorMsg = t.getMessage() != null ? t.getMessage().replace("\"", "'") : "Unknown";
                String errorResponse = "{\"messageType\":\"CHALLENGE_RESPONSE\"," +
                        "\"hmac\":\"CLIENT_ERROR\"," +
                        "\"launcherId\":\"unknown\"," +
                        "\"launcherName\":\"Error: " + errorMsg + "\"}";
                sendPluginMessage(errorResponse, context.responseSender());
                LOGGER.info("[Hidder] Error response sent");
            } catch (Exception ignored) {
                LOGGER.error("[Hidder] FATAL: Could not send error response either: " + ignored.getMessage());
            }
        }
    }

    private String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int keyIndex = json.indexOf(searchKey);
        if (keyIndex == -1)
            return "";

        int valueStart = keyIndex + searchKey.length();
        char firstChar = json.charAt(valueStart);

        if (firstChar == '"') {
            int start = valueStart + 1;
            int end = json.indexOf("\"", start);
            return json.substring(start, end);
        } else {
            int end = valueStart;
            while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
                end++;
            }
            return json.substring(valueStart, end);
        }
    }

    private String getLauncherDisplayName(String launcherId) {
        switch (launcherId) {
            case "prism":
                return "Prism Launcher";
            case "multimc":
                return "MultiMC";
            case "curseforge":
                return "CurseForge";
            case "atlauncher":
                return "ATLauncher";
            case "modrinth":
                return "Modrinth App";
            case "gdlauncher":
                return "GDLauncher";
            case "technic":
                return "Technic Launcher";
            case "ftb":
                return "FTB App";
            case "lunar":
                return "Lunar Client";
            case "badlion":
                return "Badlion Client";
            case "feather":
                return "Feather Client";
            case "labymod":
                return "LabyMod";
            case "tlauncher":
                return "TLauncher";
            case "sklauncher":
                return "SKLauncher";
            default:
                return "Unknown";
        }
    }

    private void announcePresenceToServer(PacketSender sender) {
        try {
            String announceJson = "{\"messageType\":\"ANNOUNCE_PRESENCE\",\"modId\":\"hidder\",\"version\":\"1.21.10\",\"capabilities\":[\"modlist_request\"]}";
            sendPluginMessage(announceJson, sender);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendModListResponse(ClientPlayNetworking.Context context, String checkId) {
        try {
            String jsonResponse = generateSystemInfoResponse(checkId);
            sendPluginMessage(jsonResponse, context.responseSender());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendPluginMessage(String message, PacketSender sender) {
        try {
            FriendlyByteBuf buf = new FriendlyByteBuf(Unpooled.buffer());
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            buf.writeBytes(messageBytes);
            ModSeekerPayload payload = new ModSeekerPayload(buf);
            sender.sendPacket(payload);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String generateSystemInfoResponse(String checkId) {
        try {
            List<String> mods = getInstalledMods();
            List<String> resourcePacks = getResourcePacks();
            List<String> shaderPacks = getShaderPacks();

            StringBuilder rawData = new StringBuilder();
            rawData.append("checkId=").append(checkId).append("|");

            rawData.append("mods=");
            for (int i = 0; i < mods.size(); i++) {
                if (i > 0)
                    rawData.append(",");
                rawData.append(mods.get(i));
            }
            rawData.append("|");

            rawData.append("resourcePacks=");
            for (int i = 0; i < resourcePacks.size(); i++) {
                if (i > 0)
                    rawData.append(",");
                rawData.append(resourcePacks.get(i));
            }
            rawData.append("|");

            rawData.append("shaderPacks=");
            for (int i = 0; i < shaderPacks.size(); i++) {
                if (i > 0)
                    rawData.append(",");
                rawData.append(shaderPacks.get(i));
            }

            // Append Layer 3 nonce for session binding
            rawData.append("|").append("nonce=").append(layer3Nonce != null ? layer3Nonce : "none");

            // Compute inner HMAC of the data (everything up to this point)
            // This HMAC is verified server-side to ensure data integrity
            String innerHmac = "";
            if (NativeBridge.isLoaded()) {
                innerHmac = NativeBridge.computeHmac(rawData.toString());
                LOGGER.info("[Hidder] Layer 3 inner HMAC computed");
            }
            rawData.append("|").append("innerHmac=").append(innerHmac);

            String encryptedData = "";
            String errorCode = "";

            if (!NativeBridge.isLoaded()) {
                errorCode = "DLL_NOT_LOADED";
            } else {
                encryptedData = NativeBridge.encrypt(rawData.toString());
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

            StringBuilder response = new StringBuilder();
            response.append("{\"messageType\":\"RESPONSE_MODLIST_ENCRYPTED\",");
            response.append("\"modId\":\"").append(MOD_ID).append("\",");
            response.append("\"version\":\"").append(VERSION).append("\",");
            if (!encryptedData.isEmpty()) {
                response.append("\"ciphertext\":\"").append(encryptedData).append("\"");
            } else {
                response.append("\"ciphertext\":\"").append(errorCode).append("\"");
            }
            response.append("}");

            return response.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "{\"messageType\":\"RESPONSE_MODLIST_ENCRYPTED\",\"ciphertext\":\"JAVA_EXCEPTION\"}";
        }
    }

    private List<String> getInstalledMods() {
        ArrayList<String> mods = new ArrayList<String>();
        try {
            FabricLoader.getInstance().getAllMods().forEach(modContainer -> {
                String modId = modContainer.getMetadata().getId();
                String version = modContainer.getMetadata().getVersion().getFriendlyString();
                String modEntry = modId + ":" + version;
                if (modId.equals("fabricloader") || modId.equals("fabric-api") || !modId.startsWith("fabric-")) {
                    mods.add(modEntry);
                }
            });
        } catch (Exception e) {
            // Return empty list when detection fails instead of hardcoded fake values
            e.printStackTrace();
        }
        return mods;
    }

    private List<String> getResourcePacks() {
        ArrayList<String> resourcePacks = new ArrayList<String>();
        try {
            File[] packFiles;
            File resourcePacksFolder = new File("resourcepacks");
            if (resourcePacksFolder.exists() && resourcePacksFolder.isDirectory()
                    && (packFiles = resourcePacksFolder.listFiles()) != null) {
                for (File packFile : packFiles) {
                    if (packFile.isDirectory()) {
                        resourcePacks.add(packFile.getName());
                        continue;
                    }
                    if (!packFile.getName().endsWith(".zip"))
                        continue;
                    resourcePacks.add(packFile.getName().substring(0, packFile.getName().lastIndexOf(".zip")));
                }
            }
            if (resourcePacks.isEmpty()) {
                resourcePacks.add("default");
            }
        } catch (Exception e) {
            // Return default value when detection fails instead of hardcoded fake values
            resourcePacks.add("default");
            e.printStackTrace();
        }
        return resourcePacks;
    }

    private List<String> getShaderPacks() {
        ArrayList<String> shaderPacks = new ArrayList<String>();
        try {
            File[] packFiles;
            File shaderPacksFolder = new File("shaderpacks");
            if (shaderPacksFolder.exists() && shaderPacksFolder.isDirectory()
                    && (packFiles = shaderPacksFolder.listFiles()) != null) {
                for (File packFile : packFiles) {
                    if (packFile.isDirectory()) {
                        shaderPacks.add(packFile.getName());
                        continue;
                    }
                    if (!packFile.getName().endsWith(".zip"))
                        continue;
                    shaderPacks.add(packFile.getName().substring(0, packFile.getName().lastIndexOf(".zip")));
                }
            }
            if (shaderPacks.isEmpty()) {
                shaderPacks.add("none");
            }
        } catch (Exception e) {
            // Return default value when detection fails instead of hardcoded fake values
            shaderPacks.add("none");
            e.printStackTrace();
        }
        return shaderPacks;
    }

    public record ModSeekerPayload(FriendlyByteBuf data) implements CustomPacketPayload {
        public static final CustomPacketPayload.Type<ModSeekerPayload> ID = new CustomPacketPayload.Type<>(MODSEEKER_IDENTIFIER);
        public static final StreamCodec<RegistryFriendlyByteBuf, ModSeekerPayload> CODEC = StreamCodec.of(
                (buf, value) -> buf.writeBytes(value.data.copy()),
                buf -> new ModSeekerPayload(new FriendlyByteBuf(buf.readBytes(buf.readableBytes()))));

        @Override
        public CustomPacketPayload.Type<? extends CustomPacketPayload> type() {
            return ID;
        }
    }
}
