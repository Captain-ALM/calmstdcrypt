package com.captainalm.lib.stdcrypt.digest;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class allows for obtaining {@link DigestInputStream} and {@link DigestOutputStream} using the specified algorithm.
 *
 * @author Captain ALM
 */
public final class DigestProvider implements Cloneable {
    private MessageDigest digest;
    private boolean shouldClone;

    /**
     * Constructs a new digest provider with the specified algorithm.
     *
     * @param algorithm The algorithm of the digest.
     * @throws NullPointerException algorithm is null.
     * @throws NoSuchAlgorithmException The algorithm does not exist.
     */
    public DigestProvider(String algorithm) throws NoSuchAlgorithmException {
        this(algorithm, false);
    }

    /**
     * Constructs a new digest provider with the specified algorithm
     * and if the digest should be cloned for created streams.
     *
     * @param algorithm The algorithm of the digest.
     * @param shouldClone The digest should be cloned when creating streams.
     * @throws NullPointerException algorithm is null.
     * @throws NoSuchAlgorithmException The algorithm does not exist.
     */
    public DigestProvider(String algorithm, boolean shouldClone) throws NoSuchAlgorithmException {
        if (algorithm == null) throw new NullPointerException("algorithm is null");
        digest = MessageDigest.getInstance(algorithm);
        this.shouldClone = shouldClone;
    }

    /**
     * Gets the digest input stream for this class.
     * NOTE: If using any other streams on this digest, and {@link #digestClonedForStreams()} is false,
     * The current calculated digest for this stream changes for all the other streams.
     *
     * @param inputStream The input stream to get the digest for.
     * @return The digest input stream.
     */
    public DigestInputStream getDigestInputStream(InputStream inputStream) {
        if (inputStream == null) throw new NullPointerException("inputStream is null");
        digest.reset();
        try {
            return new DigestInputStream(inputStream, (shouldClone) ? (MessageDigest) digest.clone() : digest);
        } catch (CloneNotSupportedException e) {
            return new DigestInputStream(inputStream, digest);
        }
    }

    /**
     * Gets the digest output stream for this class.
     * NOTE: If using any other streams on this digest, and {@link #digestClonedForStreams()} is false,
     * The current calculated digest for this stream changes for all the other streams.
     *
     * @param outputStream The output stream to get the digest for.
     * @return The digest output stream.
     */
    public DigestOutputStream getDigestOutputStream(OutputStream outputStream) {
        if (outputStream == null) throw new NullPointerException("outputStream is null");
        digest.reset();
        try {
            return new DigestOutputStream(outputStream, (shouldClone) ? (MessageDigest) digest.clone() : digest);
        } catch (CloneNotSupportedException e) {
            return new DigestOutputStream(outputStream, digest);
        }
    }

    /**
     * Gets the algorithm of this provider.
     *
     * @return The algorithm.
     */
    public String getAlgorithm() {
        return digest.getAlgorithm();
    }

    /**
     * Gets the length of the algorithm in bytes.
     *
     * @return The length in bytes.
     */
    public int getLength() {
        return digest.getDigestLength();
    }

    /**
     * Gets whether {@link MessageDigest}s are cloned for streams.
     *
     * @return If the digests are cloned.
     */
    public boolean digestClonedForStreams() {
        return shouldClone;
    }

    /**
     * Gets the digest of the specified array.
     * NOTE: If using any streams on this digest, and {@link #digestClonedForStreams()} is false,
     * The current calculated digest for all these streams are reset.
     *
     * @param dataIn The byte array to find the digest of.
     * @return The digest array.
     */
    public byte[] getDigestOf(byte[] dataIn) {
        digest.reset();
        return digest.digest(dataIn);
    }

    /**
     * Clones this object.
     *
     * @return The clone of this object.
     */
    @Override
    public Object clone() {
        try {
            return new DigestProvider(digest.getAlgorithm(), shouldClone);
        } catch (NoSuchAlgorithmException e) {
            return this;
        }
    }

    /**
     * Gets the instance for MD5.
     *
     * @param shouldClone The digest should be cloned when creating streams.
     * @return The DigestProvider for MD5 or null.
     */
    public static DigestProvider getMD5Instance(boolean shouldClone) {
        try {
            return new DigestProvider("MD5", shouldClone);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Gets the instance for SHA-1.
     *
     * @param shouldClone The digest should be cloned when creating streams.
     * @return The DigestProvider for SHA-1 or null.
     */
    public static DigestProvider getSHA1Instance(boolean shouldClone) {
        try {
            return new DigestProvider("SHA-1", shouldClone);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Gets the instance for SHA-256.
     *
     * @param shouldClone The digest should be cloned when creating streams.
     * @return The DigestProvider for SHA-256 or null.
     */
    public static DigestProvider getSHA256Instance(boolean shouldClone) {
        try {
            return new DigestProvider("SHA-256", shouldClone);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * Gets the instance for SHA-512.
     *
     * @param shouldClone The digest should be cloned when creating streams.
     * @return The DigestProvider for SHA-512 or null.
     */
    public static DigestProvider getSHA512Instance(boolean shouldClone) {
        try {
            return new DigestProvider("SHA-512", shouldClone);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
