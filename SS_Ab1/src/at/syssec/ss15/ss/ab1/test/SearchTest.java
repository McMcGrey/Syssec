package at.syssec.ss15.ss.ab1.test;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import at.syssec.ss15.ss.ab1.RSA;
import at.syssec.ss15.ss.ab1.impl.Kohlbacher_Wutti.RSAImpl;

public class SearchTest {

	RSA tools = new RSAImpl();


	@Test
	public void testEncryption() {

		byte[] message = "Das ist ein Sysec-Test".getBytes();

		BigInteger p = tools.generatePrime(20);

		BigInteger q = tools.generatePrime(20);

		BigInteger e = tools.generateEncryptionExponent(p, q);

		BigInteger d = tools.generateDecryptionExponent(p, q, e);

		BigInteger n = p.multiply(q);
		byte[] cipher = tools.encrypt(message, n, e);

		byte[] message_decrypted = tools.decrypt(cipher, n, d);

		Assert.assertArrayEquals(message, message_decrypted);


	}

	@Test
	public void test_Encryption_multiple_times_with_small_keys() {
		for (int i = 0 ; i < 49 ; i++) {
			byte[] message = "Das ist ein Sysec-Test".getBytes();

			BigInteger p = tools.generatePrime(20);

			BigInteger q = tools.generatePrime(20);

			BigInteger e = tools.generateEncryptionExponent(p, q);

			BigInteger d = tools.generateDecryptionExponent(p, q, e);

			BigInteger n = p.multiply(q);
			byte[] cipher = tools.encrypt(message, n, e);

			byte[] message_decrypted = tools.decrypt(cipher, n, d);

			Assert.assertArrayEquals(message, message_decrypted);

		}
	}

	@Test
	public void test_Encryption_multiple_times_with_large_keys() {
		for (int i = 0 ; i < 50 ; i++) {
			byte[] message = "Das ist ein Sysec-Test".getBytes();

			BigInteger p = tools.generatePrime(1024);

			BigInteger q = tools.generatePrime(1024);

			BigInteger e = tools.generateEncryptionExponent(p, q);

			BigInteger d = tools.generateDecryptionExponent(p, q, e);

			BigInteger n = p.multiply(q);
			byte[] cipher = tools.encrypt(message, n, e);

			byte[] message_decrypted = tools.decrypt(cipher, n, d);
			if( message.length != message_decrypted.length ) {
				System.out.println();
			}

			Assert.assertArrayEquals(message, message_decrypted);

		}
	}

}

