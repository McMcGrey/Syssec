package at.syssec.ss15.ss.ab1.impl.Nachnamen;

import java.math.BigInteger;

import at.syssec.ss15.ss.ab1.RSA;

public class RSAImpl implements RSA {

	@Override
	public BigInteger generatePrime(int n) {
        int bits = (int)Math.ceil(Math.log(Math.pow(10,n))/(Math.log(2)));
        BigInteger prime = null;
        while (prime == null && prime.toString().length() != n) {
            prime = new BigInteger(bits,1000,new Random(System.currentTimeMillis()));
        }
		return prime;
	}

	@Override
	public BigInteger generateEncryptionExponent(BigInteger p, BigInteger q) {
        BigInteger phi = (p-1)*(q-1);
        int bits = (int)Math.ceil(Math.log(Math.pow(10,phi))/(Math.log(2)))/2;
        BigInteger e = new BigInteger(bits,1000,new Random(System.currentTimeMillis()));
        while (1 <= e || e >= phi) {
            e = new BigInteger(bits,1000,new Random(System.currentTimeMillis()));
        }
		return e;//2^16+1 ueblich um Low-Exponent-Attacke zu verhindern
	}

	@Override
	public BigInteger generateDecryptionExponent(BigInteger p, BigInteger q, BigInteger e) {
        BigInteger phi = (p-1)*(q-1);
        int g, r, s, t;
        u=t=1;
        v=s=0;
        while (b>0)
        {
            g=phi/e;
            r=phi-g*e; phi=e; e=r;
            r=u-g*s; u=s; s=r;
            r=v-g*t; v=t; t=r;
        }
        return phi;
	}

	@Override
	public byte[] encrypt(byte[] message, BigInteger n, BigInteger e) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] decrypt(byte[] cipher, BigInteger n, BigInteger d) {
		// TODO Auto-generated method stub
		return null;
	}




}
