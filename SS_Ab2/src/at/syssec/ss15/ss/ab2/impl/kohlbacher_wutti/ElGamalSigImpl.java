package at.syssec.ss15.ss.ab2.impl.kohlbacher_wutti;

import java.math.BigInteger;

import at.syssec.ss15.ss.ab2.ElGamalSig;

public class ElGamalSigImpl implements ElGamalSig {

	@Override
	public BigInteger generatePrime(int n) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger generateGenerator(BigInteger p) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger generatePrivatePart(BigInteger p) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BigInteger generatePublicPart(BigInteger p, BigInteger g,
			BigInteger d) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ElGamalSignature sign(byte[] message, BigInteger p, BigInteger g,
			BigInteger d) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean verify(byte[] message, ElGamalSignature sig, BigInteger p,
			BigInteger g, BigInteger e) {
		// TODO Auto-generated method stub
		return false;
	}
}