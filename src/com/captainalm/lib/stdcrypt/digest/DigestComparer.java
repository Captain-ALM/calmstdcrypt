package com.captainalm.lib.stdcrypt.digest;

import java.io.IOException;
import java.io.InputStream;

/**
 * This class provides the ability to compare digests.
 *
 * @author Captain ALM
 */
public class DigestComparer {
    /**
     * Compares two digests.
     *
     * @param digest1 The first digest array.
     * @param digest2 The second digest array.
     * @return If the digests are equivalent.
     */
    public static boolean compareDigests(byte[] digest1, byte[] digest2) {
        if ((digest1 == null && digest2 != null) || (digest1 != null && digest2 == null)) return false;
        if (digest1 == digest2) return true;
        if (digest1.length != digest2.length) return false;
        for (int i = 0; i < digest1.length; i++) if (digest1[i] != digest2[i]) return false;
        return true;
    }

    /**
     * Compares a digest from an {@link InputStream} with a digest array.
     *
     * @param digest1Stream The input stream digest.
     * @param digest2 The digest array.
     * @return If the digests are equivalent.
     * @throws IOException An I/O Exception has occurred.
     */
    public static boolean compareDigests(InputStream digest1Stream, byte[] digest2) throws IOException {
        if (digest1Stream == null || digest2 == null) return false;
        if (digest2.length == 0) return false;
        int c;
        for (byte b : digest2) if ((c = digest1Stream.read()) == -1 || (byte) c != b) return false;
        return true;
    }
}
