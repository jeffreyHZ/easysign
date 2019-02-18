package org.luoyw.easysign.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;

/**
 * Created by luoyanwu on 2019/1/31.
 */
public class GmSupporter {
    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 公钥转换
     * @param encodedKey
     *  encoded according to the X.509 standard
     * @return
     */
    public static PublicKey getPubKey(String encodedKey) {
        PublicKey publicKey = null;
        try {
            java.security.spec.X509EncodedKeySpec bobPubKeySpec = new java.security.spec.X509EncodedKeySpec(
                    new BASE64Decoder().decodeBuffer(encodedKey));
            KeyFactory keyFactory;
            keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            // 取公钥匙对象
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * 私钥转换
     * @param encodedKey
     *  encoded according to the PKCS #8 standard
     * @return
     */
    public static PrivateKey getPrivateKey(String encodedKey) {
        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(encodedKey));
            KeyFactory keyFactory;
            keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * 获取证书
     * @param ins
     * @param strPassword
     * @return
     * @throws CertificateException
     * @throws NoSuchProviderException
     */
    public static X509Certificate getX509Certificate(InputStream ins,String strPassword)
            throws CertificateException, NoSuchProviderException
    {

        try
        {
            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
            KeyStore keyStore = KeyStore.getInstance("PKCS12", provider);
            keyStore.load(ins, strPassword.toCharArray());
            String keyAlias = null;
            Enumeration<String> enumas = keyStore.aliases();
            if (enumas.hasMoreElements())
            {
                keyAlias = (String)enumas.nextElement();
            }
           return (X509Certificate)keyStore.getCertificate(keyAlias);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally
        {
            if (ins != null)
            {
                if (null != ins)
                {
                    try
                    {
                        ins.close();
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();
                    }
                }
            }

        }
        return null;
    }

    /**
     * 通过PFX文件获得私钥
     * @param strPfx pfx文件路径
     * @param strPassword pfx文件密码
     * @return 私钥
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static PrivateKey GetPvkformPfx(String strPfx, String strPassword)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException
    {
        PrivateKey prikey = null;

        char[] nPassword = null;
        if ( (strPassword == null) || strPassword.trim().equals(""))
        {
            nPassword = null;
        }
        else
        {
            nPassword = strPassword.toCharArray();
        }
        KeyStore ks = getKsformPfx(strPfx, strPassword);
        String keyAlias = getAlsformPfx(strPfx, strPassword);
        prikey = (PrivateKey)ks.getKey(keyAlias, nPassword);
        return prikey;
    }

    public static PrivateKey GetPvkformPfx(InputStream pfx, String strPassword)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException, NoSuchProviderException {
        PrivateKey prikey = null;

        char[] nPassword = null;
        if ( (strPassword == null) || strPassword.trim().equals(""))
        {
            nPassword = null;
        }
        else
        {
            nPassword = strPassword.toCharArray();
        }
        KeyStore ks = getKsformPfx(pfx, strPassword);
        Enumeration<String> enumas = ks.aliases();
        String keyAlias = null;
        if (enumas.hasMoreElements())
        {
            keyAlias = enumas.nextElement();
        }
        prikey = (PrivateKey)ks.getKey(keyAlias, nPassword);

        //System.out.println("private key = " + prikey);
        return prikey;
    }
    /**
     * 通过PFX文件获得KEYSTORE
     * @param strPfx
     * 				PFX文件路径
     * @param strPassword
     * 				PFX文件密码
     * @return
     * 		PFX文件KEYSTORE
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static KeyStore getKsformPfx(String strPfx, String strPassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        FileInputStream fis = null;
        try
        {
            KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
            fis = new FileInputStream(strPfx);
            char[] nPassword = null;
            if ( (strPassword == null) || strPassword.trim().equals(""))
            {
                nPassword = null;
            }
            else
            {
                nPassword = strPassword.toCharArray();
            }
            ks.load(fis, nPassword);

            return ks;
        }
        catch (FileNotFoundException e)
        {
            e.printStackTrace();
        }
        finally
        {
            if (null != fis)
            {
                try
                {
                    fis.close();
                }
                catch (IOException e)
                {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    /**
     * 通过PFX文件流获得KEYSTORE
     * @param fis
     * 			PFX文件流
     * @param strPassword
     * 			PFX文件密码
     * @return
     * 		PFX文件KEYSTORE
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static KeyStore getKsformPfx(InputStream fis, String strPassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {

        char[] nPassword = null;
        if ( (strPassword == null) || strPassword.trim().equals(""))
        {
            nPassword = null;
        }
        else
        {
            nPassword = strPassword.toCharArray();
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12","BC");
        keyStore.load(fis, nPassword);
        return keyStore;
    }

    /**
     * 通过PFX文件获得别名
     * @param strPfx
     * 				PFX文件路径
     * @param strPassword
     * 				PFX文件密码
     * @return
     * 		PFX文件别名
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    public static String getAlsformPfx(String strPfx, String strPassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        String keyAlias = null;

        KeyStore ks = getKsformPfx(strPfx, strPassword);
        Enumeration<String> enumas = ks.aliases();
        keyAlias = null;
        if (enumas.hasMoreElements())
        {
            keyAlias = enumas.nextElement();
        }

        return keyAlias;
    }

    public static String getAlsformPfx(InputStream pfx, String strPassword)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
        String keyAlias = null;

        KeyStore ks = getKsformPfx(pfx, strPassword);
        Enumeration<String> enumas = ks.aliases();
        keyAlias = null;
        if (enumas.hasMoreElements())
        {
            keyAlias = enumas.nextElement();
        }

        return keyAlias;
    }
}
