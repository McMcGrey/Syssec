package at.syssec.ss15.ss.ab3.impl.Kohlbacher_Wutti;

import at.syssec.ss15.ss.ab3.PasswordTools;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

public class PasswordToolsImpl implements PasswordTools {

	@Override
	public SaltedHash createSaltedHash(String password) {

        SaltedHash hash = new SaltedHash();
        hash.setSalt(generateSalt(1024));
        hash.setHash(generateHash(password.getBytes(), hash.getSalt(), 1024));
		return hash;
	}

	@Override
	public boolean checkSaltedHash(String password, SaltedHash hash) {
		byte[] probPass = generateHash(password.getBytes(), hash.getSalt(), 1024);
        return Arrays.equals(hash.getHash(), probPass);
    }

	@Override
	public byte[] PBKDF2(byte[] password, byte[] salt, int iterations, int dkLen) {
        String str = "";
        try {
            str = new String(password, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        PBEKeySpec spec = new PBEKeySpec(str.toCharArray(), salt, iterations, dkLen * 8);
        SecretKeyFactory skf = null;
        try {
            skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            return skf.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
	}

    private byte[] generateSalt(int length) {
        final Random r = new SecureRandom();
        byte[] salt = new byte[length];
        r.nextBytes(salt);

        return salt;
    }

    private byte[] generateHash(byte[] pass, byte[] salt, int iterations) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            stream.write(pass);
            stream.write(salt);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte[] input = stream.toByteArray();

        for(int i = 0; i < iterations; i++) {

            md.update(input);
            input = md.digest();
        }

        return input;
    }

}
