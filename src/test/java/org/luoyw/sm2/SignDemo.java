package org.luoyw.sm2;

import org.junit.Assert;
import org.junit.Test;
import org.luoyw.easysign.cms.gm.CMSUtil;
import org.luoyw.easysign.sign.SM2SignUtil;
import org.luoyw.easysign.utils.GmSupporter;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Created by luoyanwu on 2019/2/18.
 */
public class SignDemo extends GmSupporter {
    @Test
    public void sign() throws Exception {
        //签名
        String pfxFile = "sm2.pfx";
        String pwd = "123456";
        X509Certificate X509Certificate = getX509Certificate(this.getClass().getClassLoader().getResourceAsStream(pfxFile),pwd);
        PrivateKey privateKey = GetPvkformPfx(this.getClass().getClassLoader().getResourceAsStream(pfxFile),pwd);
        byte[] plantext = "luoyw".getBytes();
        String signedValue = SM2SignUtil.sign(plantext,X509Certificate,privateKey);
        System.out.println("signed value = "+signedValue);
        //验证
        boolean verifyResult = SM2SignUtil.verifySign(Base64.getDecoder().decode(signedValue),plantext,X509Certificate.getPublicKey());
        System.out.println("verify result = "+verifyResult);
        Assert.assertTrue(verifyResult);

    }

    @Test
    public void signPkcs7() throws Exception {
        //签名
        String pfxFile = "sm2.pfx";
        String pwd = "123456";
        X509Certificate X509Certificate = getX509Certificate(this.getClass().getClassLoader().getResourceAsStream(pfxFile),pwd);
        PrivateKey privateKey = GetPvkformPfx(this.getClass().getClassLoader().getResourceAsStream(pfxFile),pwd);
        byte[] plantext = "luoyw".getBytes();
        String signedValue = CMSUtil.doSM2Sign(X509Certificate,privateKey,plantext,false);

        System.out.println("p7 signed value = "+signedValue);
        //验证
        boolean verifyResult = CMSUtil.doSM2Verify(Base64.getDecoder().decode(signedValue),plantext);
        System.out.println("p7 verify result = "+verifyResult);
        Assert.assertTrue(verifyResult);

    }
}
