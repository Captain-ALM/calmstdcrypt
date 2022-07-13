package com.captainalm.lib.stdcrypt.encryption;

import javax.crypto.Cipher;

/**
 * This interface provides the ability to obtain a {@link Cipher} and get and set its settings.
 *
 * @author Captain ALM
 */
public interface ICipherFactory {
    /**
     * Gets a new cipher instance.
     *
     * @param opmode The Cipher Operation Mode ({@link Cipher#ENCRYPT_MODE}, {@link Cipher#DECRYPT_MODE}, {@link Cipher#WRAP_MODE} and {@link Cipher#UNWRAP_MODE}).
     * @return The new cipher instance or null.
     * @throws CipherException An Exception has occurred.
     */
    Cipher getCipher(int opmode) throws CipherException;

    /**
     * Gets the name of the cipher factory.
     *
     * @return The name of the cipher factory.
     */
    String getName();

    /**
     * Gets if the cipher settings attributes have been modified.
     * Resets the flag once checked.
     *
     * @return If the attributes have been modified.
     */
    boolean cipherAttributesModified();

    /**
     * Gets the cipher settings as a byte array.
     *
     * @return The byte array of the settings.
     */
    byte[] getSettings();

    /**
     * Gets the length of the settings byte array.
     *
     * @return The length of the settings byte array.
     */
    int getSettingsLength();

    /**
     * Gets the cipher settings as a byte array without secrets.
     *
     * @return The byte array of the settings without secrets.
     */
    byte[] getSettingsNoSecrets();

    /**
     * Gets the length of the settings byte array without secrets.
     *
     * @return The length of the settings byte array without secrets.
     */
    int getSettingsNoSecretsLength();

    /**
     * Sets the cipher settings using a byte array.
     *
     * @param settingsIn The byte array to load the settings from.
     * @throws NullPointerException settingsIn is null.
     * @throws CipherException An Exception has occurred.
     */
    void setSettings(byte[] settingsIn) throws CipherException;
}
