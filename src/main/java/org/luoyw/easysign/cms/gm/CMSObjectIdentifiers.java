package org.luoyw.easysign.cms.gm;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * Created by luoyanwu on 2019/1/31.
 */
public abstract interface CMSObjectIdentifiers
{
    /*
        SM2 SM2算法标识 1.2.156.10197.1.301
        SM3WithSM2  SM3的SM2签名   1.2.156.10197.1.501
        sha1withSM2 SHA1的SM2签名  1.2.156.10197.1.502
        sha256withSM2   SHA256的SM2签名    1.2.156.10197.1.503
        sm3withRSAEncryption    SM3的RSA签名   1.2.156.10197.1.504
    */
  public static final ASN1ObjectIdentifier data = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.1");
  public static final ASN1ObjectIdentifier signedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.2");
  public static final ASN1ObjectIdentifier envelopedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.3");
  public static final ASN1ObjectIdentifier signedAndEnvelopedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.4");
  public static final ASN1ObjectIdentifier digestedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.5");
  public static final ASN1ObjectIdentifier encryptedData = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.5");
  public static final ASN1ObjectIdentifier authenticatedData = PKCSObjectIdentifiers.id_ct_authData;
  public static final ASN1ObjectIdentifier compressedData = PKCSObjectIdentifiers.id_ct_compressedData;
  public static final ASN1ObjectIdentifier authEnvelopedData = PKCSObjectIdentifiers.id_ct_authEnvelopedData;
  public static final ASN1ObjectIdentifier timestampedData = PKCSObjectIdentifiers.id_ct_timestampedData;
  public static final ASN1ObjectIdentifier id_ri = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.16");
  public static final ASN1ObjectIdentifier id_ri_ocsp_response = id_ri.branch("2");
  public static final ASN1ObjectIdentifier id_ri_scvp = id_ri.branch("4");

}
