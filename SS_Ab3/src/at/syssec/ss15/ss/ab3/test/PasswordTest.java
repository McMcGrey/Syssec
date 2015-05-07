package at.syssec.ss15.ss.ab3.test;

import at.syssec.ss15.ss.ab3.PasswordTools;
import at.syssec.ss15.ss.ab3.impl.Kohlbacher_Wutti.PasswordToolsImpl;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by loci on 07.05.2015.
 */
public class PasswordTest {

    PasswordTools tools = new PasswordToolsImpl();

    @Test
    public void goodTest() {
        String pass = "echolon&31245Test*fall";

        PasswordTools.SaltedHash hash =  tools.createSaltedHash(pass);

        Assert.assertTrue(tools.checkSaltedHash(pass, hash));
    }

    @Test
    public void badTest() {
        String pass = "echolon&31245Test*fall";

        PasswordTools.SaltedHash hash =  tools.createSaltedHash(pass);

        Assert.assertFalse(tools.checkSaltedHash(pass + "1", hash));
    }

    @Test
    public void DKTest1() {
        byte[] pass = "password".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] comp = new byte[]{(byte)0x0C, (byte)0x60, (byte)0xC8, (byte)0x0F, (byte)0x96, (byte)0x1F, (byte)0x0E, (byte)0x71,
                (byte)0xF3, (byte)0xA9, (byte)0xB5, (byte)0x24, (byte)0xAF, (byte)0x60, (byte)0x12, (byte)0x06,
                (byte)0x2F, (byte)0xE0, (byte)0x37, (byte)0xA6};
        int c = 1;
        int dkLen = 20;

        byte[] dk =  tools.PBKDF2(pass, salt, c, dkLen);

        Assert.assertArrayEquals(dk, comp);
    }

    @Test
    public void DKTest2() {
        byte[] pass = "password".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] comp = new byte[]{(byte)0xEA, (byte)0x6C, (byte)0x01, (byte)0x4D, (byte)0xC7, (byte)0x2D, (byte)0x6F, (byte)0x8C,
                (byte)0xCD, (byte)0x1E, (byte)0xD9, (byte)0x2A, (byte)0xCE, (byte)0x1D, (byte)0x41, (byte)0xF0,
                (byte)0xD8, (byte)0xde, (byte)0x89, (byte)0x57};
        int c = 2;
        int dkLen = 20;

        byte[] dk =  tools.PBKDF2(pass, salt, c, dkLen);

        Assert.assertArrayEquals(dk, comp);
    }

    @Test
    public void DKTest3() {
        byte[] pass = "password".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] comp = new byte[]{(byte)0x4B, (byte)0x00, (byte)0x79, (byte)0x01, (byte)0xB7, (byte)0x65, (byte)0x48, (byte)0x9A,
                (byte)0xBE, (byte)0xAD, (byte)0x49, (byte)0xD9, (byte)0x26, (byte)0xF7, (byte)0x21, (byte)0xD0,
                (byte)0x65, (byte)0xA4, (byte)0x29, (byte)0xC1};
        int c = 4096;
        int dkLen = 20;

        byte[] dk =  tools.PBKDF2(pass, salt, c, dkLen);

        Assert.assertArrayEquals(dk, comp);
    }

    @Test
    public void DKTest4() {
        byte[] pass = "password".getBytes();
        byte[] salt = "salt".getBytes();
        byte[] comp = new byte[]{(byte)0xEE, (byte)0xFE, (byte)0x3D, (byte)0x61, (byte)0xCD, (byte)0x4D, (byte)0xA4, (byte)0xE4,
                (byte)0xE9, (byte)0x94, (byte)0x5B, (byte)0x3D, (byte)0x6B, (byte)0xA2, (byte)0x15, (byte)0x8C,
                (byte)0x26, (byte)0x34, (byte)0xE9, (byte)0x84};
        int c = 16777216;
        int dkLen = 20;

        byte[] dk =  tools.PBKDF2(pass, salt, c, dkLen);

        Assert.assertArrayEquals(dk, comp);
    }

    @Test
    public void DKTest5() {
        byte[] pass = "passwordPASSWORDpassword".getBytes();
        byte[] salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes();
        byte[] comp = new byte[]{(byte)0x3D, (byte)0x2E, (byte)0xEC, (byte)0x4F, (byte)0xE4, (byte)0x1C, (byte)0x84, (byte)0x9B,
                (byte)0x80, (byte)0xC8, (byte)0xD8, (byte)0x36, (byte)0x62, (byte)0xC0, (byte)0xE4, (byte)0x4A,
                (byte)0x8B, (byte)0x29, (byte)0x1A, (byte)0x96, (byte)0x4C, (byte)0xF2, (byte)0xF0, (byte)0x70,
                (byte)0x38};
        int c = 4096;
        int dkLen = 25;

        byte[] dk =  tools.PBKDF2(pass, salt, c, dkLen);

        Assert.assertArrayEquals(dk, comp);
    }

    @Test
    public void DKTest6() {
        byte[] pass = "pass\0word".getBytes();
        byte[] salt = "sa\0lt".getBytes();
        byte[] comp = new byte[]{(byte)0x56, (byte)0xFA, (byte)0x6A, (byte)0xA7, (byte)0x55, (byte)0x48, (byte)0x09, (byte)0x9D,
                (byte)0xCC, (byte)0x37, (byte)0xD7, (byte)0xF0, (byte)0x34, (byte)0x25, (byte)0xE0, (byte)0xC3};
        int c = 4096;
        int dkLen = 16;

        byte[] dk =  tools.PBKDF2(pass, salt, c, dkLen);

        Assert.assertArrayEquals(dk, comp);
    }

}
