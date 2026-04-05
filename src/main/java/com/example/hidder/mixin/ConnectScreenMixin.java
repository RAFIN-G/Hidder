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
package com.example.hidder.mixin;

import com.example.hidder.NativeBridge;
import net.minecraft.client.gui.screens.ConnectScreen;
import net.minecraft.client.multiplayer.resolver.ServerAddress;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.ModifyArg;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(ConnectScreen.class)
public class ConnectScreenMixin {

    @ModifyArg(method = "connect(Lnet/minecraft/client/gui/screens/Screen;Lnet/minecraft/client/Minecraft;Lnet/minecraft/client/multiplayer/resolver/ServerAddress;Lnet/minecraft/server/ServerInfo;Z)V", at = @At(value = "INVOKE", target = "Lnet/minecraft/network/Connection;connect(Ljava/net/InetSocketAddress;ZLnet/minecraft/network/Connection$PacketListener;)Lnet/minecraft/network/Connection;"), index = 0)
    private static java.net.InetSocketAddress modifyServerAddress(java.net.InetSocketAddress address) {
        try {
            if (NativeBridge.isLoaded()) {
                long timestamp = System.currentTimeMillis();
                String signature = NativeBridge.signBeacon(timestamp);

                if (signature != null && !signature.isEmpty()) {
                    String beaconData = "HIDDER_BEACON:" + timestamp + ":" + signature;
                    String modifiedHost = address.getHostString() + "\0" + beaconData;

                    return new java.net.InetSocketAddress(
                            modifiedHost,
                            address.getPort());
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to inject beacon: " + e.getMessage());
        }

        return address;
    }
}
