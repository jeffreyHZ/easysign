/**
 *	j4sign - an open, multi-platform digital signature solution
 *	Copyright (c) 2004 Roberto Resoli - Servizio Sistema Informativo - Comune di Trento.
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
/*
 * $Header: /cvsroot/j4sign/j4sign/src/java/core/it/trento/comune/j4sign/cms/ExternalSignatureCMSSignedDataGenerator.java,v 1.7 2017/07/03 16:01:39 resoli Exp $
 * $Revision: 1.7 $
 * $Date: 2017/07/03 16:01:39 $
 */

package org.luoyw.easysign.cms.gm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;


/**
 * A class for generating a CMS (PKCS#7) signature message, where encryption
 * procedure is kept external.
 * <p>
 * This enables the use of cryptographic tokens, such as Smart Cards, where
 * private key is not extractable and encryption has to be done on the token.
 * </p>
 * <br/>
 * This has also the effect of completely separate the digest encryption process
 * from the message encapsulation. This is useful in signing environments, such
 * as applets, where is desirable to avoid the wheight of the provider and cms
 * library classes. See
 * {@link it.trento.comune.j4sign.examples.SimpleSignApplet}
 * <p>
 * <code>ExternalSignatureCMSSignedDataGenerator</code> is an alternative
 * implementation of <code>org.bouncycastle.cms.CMSSignedDataGenerator</code>. <br/>
 * Alternative implementation has been preferred to subclassing, because the
 * signer info generator inner class has been promoted to the indipendent
 * {@link ExternalSignatureSignerInfoGenerator}.
 * </p>
 * <p>
 * Here follows an example of usage; for a complete example, see
 * {@link it.trento.comune.j4sign.examples.CLITest}source code.
 * 
 * <pre>
 * 
 *   ExternalSignatureCMSSignedDataGenerator gen = new ExternalSignatureCMSSignedDataGenerator();
 *          		
 *   //{@link ExternalSignatureSignerInfoGenerator} encapsulates SignerInfos,
 *   //and is used in {@link #generate(org.bouncycastle.cms.CMSProcessable, boolean)} method.
 *  
 *   ExternalSignatureSignerInfoGenerator signerGenerator = new ExternalSignatureSignerInfoGenerator(
 *                                                                CMSSignedDataGenerator.DIGEST_MD5,
 *                                                                CMSSignedDataGenerator.ENCRYPTION_RSA);
 *   try {
 *       //Obtain bytes to sign; 
 *       //note that this implementation includes a timestamp
 *       //as an authenticated attribute, then bytesToSign is every time different, 
 *       //even if signing the same data.
 *       //The timestamp should be notified and accepted by the signer along data to sign
 *       //BEFORE he applies encryption with his private key.
 *       //The timestamp is used during verification to check that signature time is 
 *       //in signing certificate validity time range.
 *  
 *       byte[] bytesToSign = signerGenerator.getBytesToSign(PKCSObjectIdentifiers.data, msg, &quot;BC&quot;);
 *            							
 *       // Digest generation. Digest algorithm must match the one passed to ExternalSignatureSignerInfoGenerator
 *       // constructor above (MD5, in this case).
 *       MessageDigest md = MessageDigest.getInstance(&quot;MD5&quot;);
 *       md.update(bytesToSign);
 *       byte[] digest = md.digest();
 *            				
 *       byte[] signedBytes = null;  //will contain encripted digest
 *       byte[] certBytes = null;	//will contain DER encoded certificate
 *  
 *       //Digest encryption and signer certificate retrieval (using a PKCS11 token, for example)
 *       // Encryption algorithm must match the one passed to ExternalSignatureSignerInfoGenerator
 *       // constructor above (RSA, in this case).
 *                           .
 *                           .	
 *                           .
 *  
 *       if ((certBytes != null) &amp;&amp; (signedBytes != null)) {
 *  			
 *           //build java Certificate object. 
 *           java.security.cert.CertificateFactory cf = 
 *                               java.security.cert.CertificateFactory.getInstance(&quot;X.509&quot;);
 *           java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(certBytes);
 *           java.security.cert.X509Certificate javaCert = 
 *                			(java.security.cert.X509Certificate) cf.generateCertificate(bais);
 *                									
 *           //pass encrypted digest and certificate to the SignerInfo generator
 *           signerGenerator.setCertificate(javaCert);
 *           signerGenerator.setSignedBytes(signedBytes);
 * 
 *           //pass the signer info generator to the cms generator
 *           gen.addSignerInf(signerGenerator);
 * 								
 *           //generating a cert store with signer certificate into.
 *           //The store could contain also the root certificate and CRLS
 *           ArrayList certList = new ArrayList();
 *           certList.add(javaCert);
 * 			CertStore store = CertStore.getInstance(&quot;Collection&quot;,
 *                                                   new CollectionCertStoreParameters(certList), 
 *                                                   &quot;BC&quot;);
 *           //pass cert store to the cms generator
 *           gen.addCertificatesAndCRLs(store);
 *                
 *           //Finally, generate CMS message.
 *           CMSSignedData s = gen.generate(msg, true);
 *       }
 *    } catch (Exception ex) {
 *            ...Exception mangement ...
 *    }
 * </pre>
 * 
 * </p>
 * 
 * @author Roberto Resoli
 * @version $Revision: 1.7 $ $Date: 2017/07/03 16:01:39 $
 * 
 */
public class ExternalSignatureCMSSignedDataGenerator {

	/**
	 * The set of certificates useful for this message. This could include
	 * besides sign certificate for verifying signature, the Certification
	 * Authority root certificate and, in between, those necessary to complete
	 * certification path.
	 */
	private ArrayList<ASN1Object> certs = new ArrayList();

	/**
	 * Certificate Revocation Lists to include in CMS message. The actual
	 * implementation of <code>org.bouncycastle.cms.SignerInformation</code>
	 * class dos not use CRLS in signature verification.
	 */
	private ArrayList<ASN1Object> crls = new ArrayList();

	/**
	 * The repository of {@link ExternalSignatureSignerInfoGenerator}objects,
	 * one for signer. In the regular
	 * <code>org.bouncycastle.cms.CMSSignedDataGenerator</code> the base type
	 * was the nested <code>SignerInf</code> class.
	 */
	private ArrayList signerInfs = new ArrayList();

	/**
	 * add the certificates and CRLs contained in the given CertStore to the
	 * pool that will be included in the encoded signature block.
	 * <p>
	 * Note: this assumes the CertStore will support null in the get methods.
	 * 
	 * @param certStore
	 * @throws CertStoreException
	 * @throws CMSException
	 */
	public void addCertificatesAndCRLs(CertStore certStore)
			throws CertStoreException, CMSException {
		//
		// divide up the certs and crls.
		//
		try {
			Iterator it = certStore.getCertificates(null).iterator();

			while (it.hasNext()) {
				X509Certificate c = (X509Certificate) it.next();

				certs.add(org.bouncycastle.asn1.x509.Certificate
						.getInstance((ASN1Sequence) makeObj(c.getEncoded())));
			}
		} catch (IOException e) {
			throw new CMSException("error processing certs", e);
		} catch (CertificateEncodingException e) {
			throw new CMSException("error encoding certs", e);
		}

		try {
			Iterator it = certStore.getCRLs(null).iterator();

			while (it.hasNext()) {
				X509CRL c = (X509CRL) it.next();

				crls.add(CertificateList.getInstance((ASN1Sequence) makeObj(c
						.getEncoded())));
			}
		} catch (IOException e) {
			throw new CMSException("error processing crls", e);
		} catch (CRLException e) {
			throw new CMSException("error encoding crls", e);
		}
	}

	/**
	 * Used internally by {@link #makeAlgId(String, byte[])}
	 */
	private ASN1Primitive makeObj(byte[] encoding) throws IOException {
		if (encoding == null) {
			return null;
		}

		ByteArrayInputStream bIn = new ByteArrayInputStream(encoding);
		ASN1InputStream aIn = new ASN1InputStream(bIn);

		return aIn.readObject();
	}

	/**
	 * internally used to generate asn.1 Algorithm Identifiers form string OIDs
	 * and parameters.
	 * 
	 * @param oid
	 *            The ObjectIdentifier as <code>String</code>.
	 * @param params
	 *            Eventual algorithm parameters; null if no parameter is
	 *            required.
	 * @return the <code>org.bouncycastle.asn1.x509.AlgoriyhmIdentifier</code>
	 *         for the given OIDs and parameters.
	 * @throws IOException
	 */
	private AlgorithmIdentifier makeAlgId(String oid, byte[] params)
			throws IOException {
		if (params != null) {
			return new AlgorithmIdentifier(new DERObjectIdentifier(oid),
					makeObj(params));
		} else {
			return new AlgorithmIdentifier(new DERObjectIdentifier(oid),
					new DERNull());
		}
	}

	/**
	 * adds all the information necessary to build the
	 * <code>org.bouncycastle.asn1.cms.SignerInfo</code> about a signer.
	 * 
	 * @param si
	 *            - the {@link ExternalSignatureSignerInfoGenerator}object that
	 *            ownes informations about a single signer.
	 */
	public void addSignerInf(ExternalSignatureSignerInfoGenerator si) {

		signerInfs.add(si);

	}

	/**
	 * generate a CMS Signed Data object using the previously passed
	 * {@link ExternalSignatureSignerInfoGenerator} objects; if encapsulate is
	 * true a copy of the message will be included in the signature.
	 */
	public CMSSignedData generate(CMSProcessable content, boolean encapsulate)

	throws NoSuchAlgorithmException, NoSuchProviderException, CMSException,
			InvalidAlgorithmParameterException, CertStoreException {

		// DEREncodableVector signerInfos = new DEREncodableVector();
		// DEREncodableVector digestAlgs = new DEREncodableVector();

		ASN1EncodableVector digestAlgs = new ASN1EncodableVector();
		ASN1EncodableVector signerInfos = new ASN1EncodableVector();

		ASN1ObjectIdentifier contentTypeOID =  CMSObjectIdentifiers.data;
		
		
		//
		// add the SignerInfo objects
		//
		Iterator it = signerInfs.iterator();

		// raccoglierà i certificati dei firmatari
		// ArrayList certList = new ArrayList();

		while (it.hasNext()) {
			AlgorithmIdentifier digAlgId, encAlgId;
			ExternalSignatureSignerInfoGenerator externalSigner = (ExternalSignatureSignerInfoGenerator) it
					.next();
			try {
				digAlgId = makeAlgId(externalSigner.getDigestAlgOID(),
						externalSigner.getDigestAlgParams());

				digestAlgs.add(digAlgId);

				signerInfos.add(externalSigner.generate());

				// certList.add(externalSigner.getCertificate());
			} catch (IOException e) {
				throw new CMSException("encoding error.", e);
			} catch (CertificateEncodingException e) {
				throw new CMSException("error creating sid.", e);
			} catch (Exception e)
			{
			    e.printStackTrace();
			}
		}

		ASN1Set certificates = null;

		if (certs.size() != 0) {
			certificates = createBerSetFromList(certs);
		}
		/*
		 * if (certs.size() != 0) { DEREncodableVector v = new
		 * DEREncodableVector();
		 * 
		 * it = certs.iterator(); while (it.hasNext()) { v.add((DEREncodable)
		 * it.next()); }
		 * 
		 * certificates = new DERSet(v); }
		 */
		ASN1Set certrevlist = null;

		if (crls.size() != 0) {
			certrevlist = createBerSetFromList(crls);
		}
		/*
		 * if (crls.size() != 0) { DEREncodableVector v = new
		 * DEREncodableVector();
		 * 
		 * it = crls.iterator(); while (it.hasNext()) { v.add((DEREncodable)
		 * it.next()); }
		 * 
		 * certrevlist = new DERSet(v); }
		 */

		ASN1OctetString octs = null;
		if (encapsulate) {

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try {
				content.write(bOut);
			} catch (IOException e) {
				throw new CMSException("encapsulation error.", e);
			}

			octs = new BERConstructedOctetString(bOut.toByteArray());

		}

		ContentInfo encInfo = new ContentInfo(contentTypeOID, octs);

		GmSignedData sd = new GmSignedData(new DERSet(digestAlgs), encInfo,
				certificates, certrevlist, new DERSet(signerInfos));

		ContentInfo contentInfo = new ContentInfo(CMSObjectIdentifiers.signedData, sd);

		return new CMSSignedData(content, contentInfo);
	}

	static ASN1Set createBerSetFromList(ArrayList<ASN1Object> asn1Objects) {
		ASN1EncodableVector v = new ASN1EncodableVector();

		for (Iterator it = asn1Objects.iterator(); it.hasNext();) {
			v.add((ASN1Object) it.next());
		}

		return new DERSet(v);
	}
}