// SPDX-FileCopyrightText: 2026 ModSeeker
// SPDX-License-Identifier: AGPL-3.0-or-later

package com.example.hidder;

import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

final class NetworkCompatibility {
    private NetworkCompatibility() {
    }

    static CustomPacketPayload.Type<HidderFabric.ModSeekerPayload> createType() {
        return new CustomPacketPayload.Type<>(Identifier.fromNamespaceAndPath("modseeker", "modlist"));
    }

    static void register(StreamCodec<RegistryFriendlyByteBuf, HidderFabric.ModSeekerPayload> codec) {
        PayloadTypeRegistry.serverboundPlay().register(HidderFabric.ModSeekerPayload.TYPE, codec);
        PayloadTypeRegistry.clientboundPlay().register(HidderFabric.ModSeekerPayload.TYPE, codec);
    }
}
