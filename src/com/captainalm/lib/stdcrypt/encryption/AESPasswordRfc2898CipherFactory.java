package com.captainalm.lib.stdcrypt.encryption;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

/**
 * This class provides an AES cipher that uses Rfc2898 for key generation and a string password.
 *
 * @author Captain ALM
 */
public class AESPasswordRfc2898CipherFactory implements ICipherFactory {
    protected static final int iVectorDefaultSize = 16;
    protected static final int saltDefaultSize = 32;
    protected static final int iterations = 2000;
    protected static final int keySize = 256;

    protected final Object slock = new Object();

    protected String password; //Cannot be exported in settings
    protected byte[] salt;
    protected byte[] iVector;
    protected byte[] passwordCache;

    protected boolean outputSalt;
    protected boolean outputIVector;

    protected boolean haveAttributesChanged;

    /**
     * Constructs a new instance of AESPasswordRfc2898CipherFactory with the specified password.
     *
     * @param password The password to use.
     * @throws NullPointerException password is null.
     */
    public AESPasswordRfc2898CipherFactory(String password) {
        this(password, null, null);
    }

    /**
     * Constructs a new instance of AESPasswordRfc2898CipherFactory with the specified password, salt and initialization vector.
     *
     * @param password The password to use.
     * @param salt The salt to use or null.
     * @param initializationVector The initialization vector to use or null.
     * @throws NullPointerException password is null.
     * @throws IllegalArgumentException salt or initializationVector is larger than 255.
     */
    public AESPasswordRfc2898CipherFactory(String password, byte[] salt, byte[] initializationVector) {
        setPassword(password);
        setSalt(salt);
        setInitializationVector(initializationVector);
        haveAttributesChanged = false;
    }

    protected void processPasswordCache() {
        if (passwordCache == null) passwordCache = password.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Gets a new cipher instance.
     *
     * @param opmode The Cipher Operation Mode ({@link Cipher#ENCRYPT_MODE}, {@link Cipher#DECRYPT_MODE}, {@link Cipher#WRAP_MODE} and {@link Cipher#UNWRAP_MODE}).
     * @return The new cipher instance or null.
     * @throws CipherException An Exception has occurred.
     */
    @Override
    public Cipher getCipher(int opmode) throws CipherException {
        try {
            if (salt == null || salt.length < 1) {
                salt = new byte[saltDefaultSize];
                SecureRandom.getInstanceStrong().nextBytes(salt);
            }

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
            SecretKeySpec secretSpec = new SecretKeySpec(keyFactory.generateSecret(pbeKeySpec).getEncoded(), "AES");

            if (iVector == null || iVector.length < 1) {
                iVector = new byte[iVectorDefaultSize];
                SecureRandom.getInstanceStrong().nextBytes(iVector);
            }
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iVector);

            Cipher toret = Cipher.getInstance("AES/CBC/PKCS5Padding");
            toret.init(opmode, secretSpec, ivSpec);
            return toret;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CipherException(e);
        }
    }

    /**
     * Gets the name of the cipher factory.
     *
     * @return The name of the cipher factory.
     */
    @Override
    public String getName() {
        return "AES Password Rfc 2898";
    }

    /**
     * Gets if the cipher settings attributes have been modified.
     * Resets the flag once checked.
     *
     * @return If the attributes have been modified.
     */
    @Override
    public boolean cipherAttributesModified() {
        synchronized (slock) {
            boolean toret = haveAttributesChanged;
            haveAttributesChanged = false;
            return toret;
        }
    }

    /**
     * Gets the cipher settings as a byte array.
     *
     * @return The byte array of the settings.
     */
    @Override
    public byte[] getSettings() {
        synchronized (slock) {
            processPasswordCache();
            byte[] toret = new byte[1 + ((passwordCache == null) ? 0 : passwordCache.length + 4) + ((salt == null) ? 0 : salt.length + 1) + ((iVector == null) ? 0 : iVector.length + 1)];
            toret[0] = (byte) (((passwordCache == null) ? 0 : 1) + ((salt == null) ? 0 : 2) + ((iVector == null) ? 0 : 4));

            int index = 1;
            if (passwordCache != null) {
                int length = passwordCache.length;

                toret[index++] = (byte) (length / 16777216);
                length %= 16777216;
                toret[index++] = (byte) (length / 65536);
                length %= 65536;
                toret[index++] = (byte) (length / 256);
                length %= 256;
                toret[index++] = (byte) (length);

                System.arraycopy(passwordCache, 0, toret, index, passwordCache.length); index += passwordCache.length;
            }

            if (salt != null) {
                toret[index++] = (byte) salt.length;
                System.arraycopy(salt, 0, toret, index, salt.length); index += salt.length;
            }

            if (iVector != null) {
                toret[index++] = (byte) iVector.length;
                System.arraycopy(iVector, 0, toret, index, iVector.length);
            }

            return toret;
        }
    }

    /**
     * Gets the length of the settings byte array.
     *
     * @return The length of the settings byte array.
     */
    @Override
    public int getSettingsLength() {
        synchronized (slock) {
            processPasswordCache();
            return 1 + ((passwordCache == null) ? 0 : passwordCache.length + 4) + ((salt == null) ? 0 : salt.length + 1) + ((iVector == null) ? 0 : iVector.length + 1);
        }
    }

    /**
     * Gets the cipher settings as a byte array without secrets.
     *
     * @return The byte array of the settings without secrets.
     */
    @Override
    public byte[] getSettingsNoSecrets() {
        synchronized (slock) {
            byte[] toret = new byte[1 + ((salt == null) ? 0 : salt.length + 1) + ((iVector == null) ? 0 : iVector.length + 1)];
            toret[0] = (byte) (((salt == null) ? 0 : 2) + ((iVector == null) ? 0 : 4));

            int index = 1;
            if (salt != null) {
                toret[index++] = (byte) salt.length;
                System.arraycopy(salt, 0, toret, index, salt.length); index += salt.length;
            }

            if (iVector != null) {
                toret[index++] = (byte) iVector.length;
                System.arraycopy(iVector, 0, toret, index, iVector.length);
            }

            return toret;
        }
    }

    /**
     * Gets the length of the settings byte array without secrets.
     *
     * @return The length of the settings byte array without secrets.
     */
    @Override
    public int getSettingsNoSecretsLength() {
        synchronized (slock) {
            return 1 + ((salt == null) ? 0 : salt.length + 1) + ((iVector == null) ? 0 : iVector.length + 1);
        }
    }

    /**
     * Sets the cipher settings using a byte array.
     *
     * @param settingsIn The byte array to load the settings from.
     * @throws NullPointerException settingsIn is null.
     * @throws CipherException      An Exception has occurred.
     */
    @Override
    public void setSettings(byte[] settingsIn) throws CipherException {
        if (settingsIn == null) throw new NullPointerException("settingsIn is null");
        if (settingsIn.length < 1) throw new CipherException("no data");
        synchronized (slock) {
            int index = 1;
            if (((settingsIn[0] & 4) == 4)) {
                int pwdLength = (settingsIn[index++] & 0xff) * 16777216;
                pwdLength += (settingsIn[index++] & 0xff) * 65536;
                pwdLength += (settingsIn[index++] & 0xff) * 256;
                pwdLength += (settingsIn[index++] & 0xff);
                if (pwdLength < 1) throw new CipherException("password length less than 1");

                passwordCache = new byte[pwdLength];
                System.arraycopy(settingsIn, index, passwordCache, 0, pwdLength); index += pwdLength;

                password = new String(passwordCache, StandardCharsets.UTF_8);
            }

            if (((settingsIn[0] & 8) == 8)) {
                int length = settingsIn[index++] & 0xff;
                if (length < 1) throw new CipherException("salt length less than 1");
                salt = new byte[length];
                System.arraycopy(settingsIn, index, salt, 0, length); index += length;
            }

            if (((settingsIn[0] & 16) == 16)) {
                int length = settingsIn[index++] & 0xff;
                if (length < 1) throw new CipherException("initializationVector length less than 1");
                iVector = new byte[length];
                System.arraycopy(settingsIn, index, iVector, 0, length);
            }
        }
    }

    /**
     * Gets the password.
     *
     * @return The password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the password.
     *
     * @param password The new password.
     * @throws NullPointerException password is null.
     */
    public void setPassword(String password) {
        if (password == null) throw new NullPointerException("password is null");
        synchronized (slock) {
            haveAttributesChanged = true;
            this.password = password;
            passwordCache = null;
        }
    }

    /**
     * Gets the salt in use.
     *
     * @return The salt.
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Sets the salt in use, set to null to generate a random salt.
     *
     * @param salt The new salt or null.
     * @throws IllegalArgumentException salt is larger than 255.
     */
    public void setSalt(byte[] salt) {
        if (salt != null && salt.length > 255) throw new IllegalArgumentException("salt is larger than 255");
        synchronized (slock) {
            haveAttributesChanged = true;
            this.salt = salt;
        }
    }

    /**
     * Gets the initialization vector.
     *
     * @return The initialization vector.
     */
    public byte[] getInitializationVector() {
        return iVector;
    }

    /**
     * Sets the initialization vector in use, set to null to generate a random initialization vector.
     *
     * @param initializationVector The new initialization vector or null.
     * @throws IllegalArgumentException initializationVector is larger than 255.
     */
    public void setInitializationVector(byte[] initializationVector) {
        if (initializationVector != null && initializationVector.length > 255) throw new IllegalArgumentException("initializationVector is larger than 255");
        synchronized (slock) {
            haveAttributesChanged = true;
            iVector = initializationVector;
        }
    }

    /**
     * Gets whether the salt is output.
     *
     * @return Is the salt output.
     */
    public boolean isOutputtingSalt() {
        return outputSalt;
    }

    /**
     * Sets if the salt is output.
     *
     * @param outputSalt Should the salt be output.
     */
    public void setOutputSalt(boolean outputSalt) {
        this.outputSalt = outputSalt;
    }

    /**
     * Gets whether the InitializationVector is output.
     *
     * @return Is the InitializationVector output.
     */
    public boolean isOutputtingInitializationVector() {
        return outputIVector;
    }

    /**
     * Sets if the InitializationVector is output.
     *
     * @param outputInitializationVector Should the InitializationVector be output.
     */
    public void setOutputInitializationVector(boolean outputInitializationVector) {
        outputIVector = outputInitializationVector;
    }
}
