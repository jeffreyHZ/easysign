package org.luoyw.easysign.cms.gm;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.luoyw.easysign.sign.SM2SignUtil;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;


/**
 * sm2 cms签名格式封装
 * 基于bouncycastle、j4sign
 * @author luoyanwu
 */
public class CMSUtil
{
    private static boolean isDebug = false;

    /**
     * p7签名 
     * @param cert
     * @param prikey
     * @param signbyte 待签名数据
     * @param isTsp 是否加时间戳签名
     * @return
     * @throws Exception
     */
    public static String doSM2Sign(X509Certificate cert,PrivateKey prikey,byte[] signbyte
    		,boolean isTsp) throws Exception
    {
        try {
            ExternalSignatureSignerInfoGenerator signerGenerator = 
                new ExternalSignatureSignerInfoGenerator(GMObjectIdentifiers.sm3.getId(), GMObjectIdentifiers.sm2p256v1.getId());
            
            ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();
//            byte[] signbyte = content.getBytes();
            CMSTypedData msg = new CMSProcessableByteArray(CMSObjectIdentifiers.data,signbyte);
//            byte[] bytesToSign = signerGenerator.getBytesToSign(
//            CMSObjectIdentifiersSM2.data, msg, "BC");
            //BigInteger[] signed = SM2SignUtil.signReturnBigInt(signbyte, prikey);
            //SM2Signature asn1Primitive = new SM2Signature(signed[0],signed[1]);
            //byte[] signedBytes = asn1Primitive.getEncoded();
            byte[] signedBytes = Base64.decode(SM2SignUtil.sign(signbyte, cert,prikey));
             // digest
//            System.out.println("length"+signedBytes.length);
            byte[] certBytes = cert.getEncoded(); // will contain DER encoded
            
            if ((certBytes != null) && (signedBytes != null)) {
                // generator
                signerGenerator.setCertificate((X509Certificate)cert);
                signerGenerator.setSignedBytes(signedBytes);
                gen.addSignerInf(signerGenerator);
                
                ArrayList certList = new ArrayList();
                certList.add(cert);
                CertStore store = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
                gen.addCertificatesAndCRLs(store);
                // Finally, generate CMS message.
                //默认不带原文
                CMSSignedData sigData = gen.generate(msg, false);
                if(isTsp)
                {
                	//sigData = addTimestamp(sigData); // to do
                }
                Base64 encoder = new Base64();
                ContentInfo contentInfo = sigData.toASN1Structure();
                String signedContent = new String(encoder.encode(contentInfo.getEncoded(ASN1Encoding.DER)));
//                System.out.println("Signed content: dl  " + signedContent + "\n");
                return signedContent;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    
    
    
    

    
    /**
     * sm2 pkcs7验签
     * @param signedData
     * @return true or false
     * @throws Exception
     */
    public static boolean doSM2Verify(byte[] signedData ,byte[] planText)
        throws Exception
    {
        
        ByteArrayInputStream inStream = new ByteArrayInputStream((signedData));
        CMSSignedData cmsSingedData = new CMSSignedData(inStream);
//        ASN1InputStream ais = new ASN1InputStream(Base64.decode(signedData));
        
        //签名值
        byte[] signed = null;
        X509Certificate cert = null;
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        CollectionStore x509s = (CollectionStore)cmsSingedData.getCertificates();
        X509CertificateHolder holder = (X509CertificateHolder)x509s.iterator().next();
        InputStream in = new ByteArrayInputStream(holder.getEncoded());
        cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
        // 获得证书信息
        CMSTypedData cmsTypeDatas = cmsSingedData.getSignedContent();
        // 获得签名者信息
        Object og = cmsSingedData.getSignerInfos();
        SignerInformationStore signers = cmsSingedData.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation)it.next();
//            System.out.println("摘要算法 =" + signer.getDigestAlgOID());
//            System.out.println("算法 =" + signer.getEncryptionAlgOID());
            signed = signer.getSignature();
        }
//        System.out.println("签名值length=" + signed.length);
        return SM2SignUtil.verifySign(signed, planText, cert.getPublicKey());
        
    }



    /**
     * Convert byte[] to S/MIME string
     * @param data
     * @return
     */
    public static String binaryToSmime(byte[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PKCS7-----\n");
        for (int i = 0; i < data.length; ) {
            byte[] chunk = Arrays.copyOfRange(data, i, (i + 63));
            sb.append(new String(chunk));
            sb.append("\n");
            i += 63;
        }
        sb.append("-----END PKCS7-----");
        return sb.toString();
    }


}
