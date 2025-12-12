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

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class NativeBridge {
    private static boolean loaded = false;

    static {
        loadLibrary();
    }

    private static void loadLibrary() {
        try {
            String libName = "hidder_vault.dll";
            InputStream in = NativeBridge.class.getResourceAsStream("/" + libName);

            if (in == null) {
                System.err.println("⚠️ Native Library not found in JAR: " + libName);
                return;
            }

            File tempFile = File.createTempFile("hidder_vault", ".dll");
            tempFile.deleteOnExit();

            try (FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[1024];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }

            System.load(tempFile.getAbsolutePath());
            loaded = true;
        } catch (Throwable e) {
            System.err.println("❌ Failed to load Native Vault: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public static native String sign(String data);

    public static native String encrypt(String data);
}
