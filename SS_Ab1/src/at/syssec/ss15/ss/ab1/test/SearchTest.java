package at.syssec.ss15.ss.ab1.test;

import java.math.BigInteger;

import org.junit.Assert;

import at.syssec.ss15.ss.ab1.RSA;
import at.syssec.ss15.ss.ab1.impl.Nachnamen.RSAImpl;

public class SearchTest {

	RSA tools = new RSAImpl();

	
	@Test
	public void testEncryption() {
		
		byte[] message = "Das ist ein SysSec-Test".getBytes();
		
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
