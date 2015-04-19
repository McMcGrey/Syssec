package at.syssec.ss15.ss.ab2.test;


import at.syssec.ss15.ss.ab2.ElGamalSig;
import at.syssec.ss15.ss.ab2.impl.kohlbacher_wutti.ElGamalSigImpl;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class SigTest {

    ElGamalSig tools = new ElGamalSigImpl();

    @Test
    public void testSignatur() {

        byte[] message = "Das ist ein SysSec-Test".getBytes();

        BigInteger p = tools.generatePrime(20);

        BigInteger g = tools.generateGenerator(p);

        BigInteger d = tools.generatePrivatePart(p);

        BigInteger e = tools.generatePublicPart(p, g, d);

        ElGamalSig.ElGamalSignature sig = tools.sign(message, p, g, d);

        Assert.assertTrue(tools.verify(message, sig, p, g, e));
    }

}
