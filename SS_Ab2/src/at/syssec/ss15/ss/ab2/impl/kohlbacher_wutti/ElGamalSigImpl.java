package at.syssec.ss15.ss.ab2.impl.kohlbacher_wutti;

import at.syssec.ss15.ss.ab2.ElGamalSig;

import java.math.BigInteger;
import java.util.Random;

public class ElGamalSigImpl implements ElGamalSig {


	@Override
	public BigInteger generatePrime(int n) {
        int bits = (int)Math.ceil(Math.log(Math.pow(10,n))/(Math.log(2)));
        BigInteger prime = new BigInteger(bits,1000,new Random(System.currentTimeMillis())); // Primzahlenerzeugung mit probability 1-(2^-1000)
        while (prime.toString().length() != n) {
            prime = new BigInteger(bits,1000,new Random(System.currentTimeMillis()));
        }
        return prime;
	}

	@Override
	public BigInteger generateGenerator(BigInteger p) {
        Random rnd = new Random();
        BigInteger gen = new BigInteger(rnd.nextInt(p.bitLength() - 1) + 1, rnd);
        while(gen.compareTo(p.subtract(BigInteger.ONE)) == 1 || gen.compareTo(BigInteger.ONE) == -1) {
            gen = new BigInteger(rnd.nextInt(p.bitLength() - 1) + 1, rnd);
        }
		return gen;
	}

	@Override
	public BigInteger generatePrivatePart(BigInteger p) {
        Random rnd = new Random();
        BigInteger d = new BigInteger(rnd.nextInt(p.bitLength() - 1) + 1, rnd);
        while(d.compareTo(p.subtract(BigInteger.valueOf(2))) == 1 || d.compareTo(BigInteger.valueOf(2)) == -1) {
            d = new BigInteger(rnd.nextInt(p.bitLength() - 1) + 1, rnd);
        }
		return d;
	}

	@Override
	public BigInteger generatePublicPart(BigInteger p, BigInteger g, BigInteger d) {
		return g.modPow(d, p);
	}

	@Override
	public ElGamalSignature sign(byte[] message, BigInteger p, BigInteger g, BigInteger d) {
        Random rnd = new Random();
        BigInteger k = new BigInteger(rnd.nextInt(p.bitLength() - 1) + 1, rnd);
        while(k.compareTo(p.subtract(BigInteger.valueOf(2))) == 1 || k.compareTo(BigInteger.valueOf(2)) == -1 || k.gcd(p.subtract(BigInteger.ONE)).intValue() != 1) {
            k = new BigInteger(rnd.nextInt(p.bitLength() - 1) + 1, rnd);
        }
        BigInteger x = new BigInteger(message);
        BigInteger minusK = k.modInverse(p);
        BigInteger r =  g.modPow(k , p);
        BigInteger s = (x.subtract(d.multiply(r))).multiply(minusK).mod(p.subtract(BigInteger.ONE));
        ElGamalSignature signature = new ElGamalSignature();
        signature.setR(r.toByteArray());    //
        signature.setS(s.toByteArray());   //delta
        System.out.println("Message: " + x);
        System.out.println("s: " + s);
        System.out.println("r: " + r);

		return signature;
	}

	@Override
	public boolean verify(byte[] message, ElGamalSignature sig, BigInteger p, BigInteger g, BigInteger e) {
        BigInteger x = new BigInteger(message);
        BigInteger r = new BigInteger(sig.getR());
        BigInteger s = new BigInteger(sig.getS());
        System.out.println("Message: " + x);
        System.out.println("s: " + s);
        System.out.println("r: " + r);
        BigInteger mes = g.modPow(x,p);
        BigInteger signatur = (e.modPow(r,p).multiply(r.modPow(s,p))).mod(p);
        System.out.println("Mess: " + mes);
        System.out.println("Sign: " + signatur);

		return mes.compareTo(signatur) == 0;
	}

}
