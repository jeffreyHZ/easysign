package org.luoyw.easysign.sign;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.luoyw.easysign.cms.gm.CMSUtil;
import org.luoyw.easysign.utils.GmSupporter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.util.Enumeration;

/**
 * Created by luoyanwu on 2017/10/31.
 * update on 2019/2/1.
 */
public class SM2SignUtil extends GmSupporter {
    private static byte[] SM2_USER_ID = "1234567812345678".getBytes();
    private static String fileSignedData;
    private static X509Certificate cert;

    /**
     * PKCS1格式签名
     *
     * @param data       待签名数据
     * @param cert       签名证书
     * @param privateKey 私钥
     * @return PKCS1格式签名值
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static String sign(byte[] data, X509Certificate cert, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, CryptoException {
        // 创建SM2Signer对象
        SM2Signer localSM2Signer = new SM2Signer();
        // 生成签名
//       cannot be cast to org.bouncycastle.jce.provider.JCEECPrivateKey
        ECPrivateKey jecpk = (ECPrivateKey) privateKey;
        BCECPrivateKey szcaSm2PriK = new BCECPrivateKey((ECPrivateKey) jecpk, null);
        ECParameterSpec localECParameterSpec = szcaSm2PriK.getParameters();
        ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                localECParameterSpec.getG(), localECParameterSpec.getN());

        ECPrivateKeyParameters localECPrivateKeyParameters = new ECPrivateKeyParameters(szcaSm2PriK.getD(), localECDomainParameters);
        ParametersWithID parametersWithID = new ParametersWithID(localECPrivateKeyParameters, SM2_USER_ID);
        localSM2Signer.init(true, parametersWithID);
        //BigInteger[] arrayOfBigInteger = localSM2Signer.generateSignature(signbyte); //bc 1.57 api 返回了大整数，后面api返回了Asn.1
        localSM2Signer.update(data, 0, data.length);
        byte[] signedValue = localSM2Signer.generateSignature();
        return Base64.toBase64String(signedValue);

    }

    /**
     * bc 1.57版本调用
     * @param signbyte
     * @param privateKey
     * @return
     * @throws CryptoException
     */
   /*public static BigInteger[] signReturnBigInt(byte[] signbyte,PrivateKey privateKey) throws CryptoException {
       // 创建SM2Signer对象
       SM2Signer localSM2Signer = new SM2Signer();
       // 生成签名 TRUE
//       cannot be cast to org.bouncycastle.jce.provider.JCEECPrivateKey
       ECPrivateKey jecpk = (ECPrivateKey) privateKey;
       BCECPrivateKey szcaSm2PriK = new BCECPrivateKey((ECPrivateKey) jecpk, null);
       ECParameterSpec localECParameterSpec =  szcaSm2PriK.getParameters();
       ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
           localECParameterSpec.getG(), localECParameterSpec.getN());
       
       ECPrivateKeyParameters localECPrivateKeyParameters = new ECPrivateKeyParameters(szcaSm2PriK.getD(),localECDomainParameters);
       ParametersWithID parametersWithID = new ParametersWithID(localECPrivateKeyParameters,SM2_USER_ID);
       localSM2Signer.init(true, parametersWithID);
       //BigInteger[] arrayOfBigInteger = localSM2Signer.generateSignature(signbyte); //bc 1.57 api 返回了大整数，后面api返回了Asn.1
       localSM2Signer.update(signbyte,0,signbyte.length);
       localSM2Signer.generateSignature();

       return arrayOfBigInteger;
   }*/

    /**
     * PKCS1 验证
     *
     * @param signedValue  签名值勤
     * @param originalText 原文
     * @param publicKey    公钥
     * @return 验证结果
     * true 正确
     * false 错误
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static boolean verifySign(byte[] signedValue, byte[] originalText, PublicKey publicKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, IOException {
        SM2Signer localSM2Signer = new SM2Signer();
        //PublicKey publicKey = cert.getPublicKey();
        ECPublicKeyParameters param = null;

        if (publicKey instanceof BCECPublicKey) {
            BCECPublicKey localECPublicKey = (BCECPublicKey) publicKey;
            ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                    localECParameterSpec.getG(), localECParameterSpec.getN());
            param = new ECPublicKeyParameters(localECPublicKey.getQ(), localECDomainParameters);
        }

        BigInteger R = null;
        BigInteger S = null;

        if (signedValue.length == 64) {
            byte[] dest = new byte[32];
            System.arraycopy(signedValue, 0, dest, 0, 32);
            R = new BigInteger(dest);
            byte[] dest1 = new byte[32];
            System.arraycopy(signedValue, 32, dest1, 0, 32);
            S = new BigInteger(dest1);
        } else {
            ByteArrayInputStream inStream = new ByteArrayInputStream(signedValue);
            ASN1InputStream asnInputStream = new ASN1InputStream(inStream);

            ASN1Primitive derObject = asnInputStream.readObject();
            if (derObject instanceof ASN1Sequence) {
                ASN1Sequence signSequence = (ASN1Sequence) derObject;
                Enumeration<ASN1Integer> enumer = signSequence.getObjects();
                R = ((ASN1Integer) enumer.nextElement()).getValue();
                S = ((ASN1Integer) enumer.nextElement()).getValue();
            }
        }
        ParametersWithID parametersWithID = new ParametersWithID(param, SM2_USER_ID);
        localSM2Signer.init(false, parametersWithID);
      /* boolean res = localSM2Signer.verifySignature(originalText, BigIntegerUtil.toPositiveInteger(R.toByteArray()),
           BigIntegerUtil.toPositiveInteger(S.toByteArray())); //bc1.57 */
        localSM2Signer.update(originalText, 0, originalText.length);
        boolean res = localSM2Signer.verifySignature(signedValue);
        return res;
    }


    /**
     * SM2 PKCS7 格式的签名
     *
     * @param x509
     * @param privateKey
     * @param contentInfoS
     * @return base64 String or null
     * @throws Exception
     */
    public static String signwithContentInfoByPkcs7(X509Certificate x509, PrivateKey privateKey, byte[] contentInfoS
            , boolean isTsp) throws
            Exception {

        return CMSUtil.doSM2Sign(x509, privateKey, contentInfoS, isTsp);
    }


}
