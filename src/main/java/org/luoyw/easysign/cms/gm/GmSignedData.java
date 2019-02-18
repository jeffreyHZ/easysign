package org.luoyw.easysign.cms.gm;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignerInfo;

import java.util.Enumeration;


public class GmSignedData extends ASN1Object
{
    private static final ASN1Integer VERSION_1 = new ASN1Integer(1L);
    private static final ASN1Integer VERSION_3 = new ASN1Integer(3L);
    private static final ASN1Integer VERSION_4 = new ASN1Integer(4L);
    private static final ASN1Integer VERSION_5 = new ASN1Integer(5L);
    private ASN1Integer version;
    private ASN1Set digestAlgorithms;
    private ContentInfo contentInfo;
    private ASN1Set certificates;
    private ASN1Set crls;
    private ASN1Set signerInfos;
    private boolean certsBer;
    private boolean crlsBer;

    public static GmSignedData getInstance(Object paramObject)
    {
        if (paramObject instanceof GmSignedData)
            return ((GmSignedData)paramObject);
        if (paramObject != null)
            return new GmSignedData(ASN1Sequence.getInstance(paramObject));
        return null;
    }

    public GmSignedData(ASN1Set paramASN1Set1, ContentInfo paramContentInfo, ASN1Set paramASN1Set2, ASN1Set paramASN1Set3, ASN1Set paramASN1Set4)
    {
        this.version = calculateVersion(paramContentInfo.getContentType(), paramASN1Set2, paramASN1Set3, paramASN1Set4);
        this.digestAlgorithms = paramASN1Set1;
        this.contentInfo = paramContentInfo;
        this.certificates = paramASN1Set2;
        this.crls = paramASN1Set3;
        this.signerInfos = paramASN1Set4;
        this.crlsBer = paramASN1Set3 instanceof BERSet;
        this.certsBer = paramASN1Set2 instanceof BERSet;
    }

    private ASN1Integer calculateVersion(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Set paramASN1Set1, ASN1Set paramASN1Set2, ASN1Set paramASN1Set3)
    {
        int i = 0;
        int j = 0;
        int k = 0;
        int l = 0;
        Enumeration localEnumeration;
        Object localObject;
        if (paramASN1Set1 != null)
        {
            localEnumeration = paramASN1Set1.getObjects();
            while (localEnumeration.hasMoreElements())
            {
                localObject = localEnumeration.nextElement();
                if (localObject instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject localASN1TaggedObject = ASN1TaggedObject.getInstance(localObject);
                    if (localASN1TaggedObject.getTagNo() == 1)
                        k = 1;
                    else if (localASN1TaggedObject.getTagNo() == 2)
                        l = 1;
                    else if (localASN1TaggedObject.getTagNo() == 3)
                        i = 1;
                }
            }
        }
        if (i != 0)
            return new ASN1Integer(5L);
        if (paramASN1Set2 != null)
        {
            localEnumeration = paramASN1Set2.getObjects();
            while (localEnumeration.hasMoreElements())
            {
                localObject = localEnumeration.nextElement();
                if (localObject instanceof ASN1TaggedObject)
                    j = 1;
            }
        }
        if (j != 0)
            return VERSION_5;
        if (l != 0)
            return VERSION_4;
        if (k != 0)
            return VERSION_3;
        if (checkForVersion3(paramASN1Set3))
            return VERSION_3;
        if (!(CMSObjectIdentifiers.data.equals(paramASN1ObjectIdentifier)))
            return VERSION_3;
        return VERSION_1;
    }

    private boolean checkForVersion3(ASN1Set paramASN1Set)
    {
        Enumeration localEnumeration = paramASN1Set.getObjects();
        while (localEnumeration.hasMoreElements())
        {
            SignerInfo localSignerInfo = SignerInfo.getInstance(localEnumeration.nextElement());
            if (localSignerInfo.getVersion().getValue().intValue() == 3)
                return true;
        }
        return false;
    }

    private GmSignedData(ASN1Sequence paramASN1Sequence)
    {
        Enumeration localEnumeration = paramASN1Sequence.getObjects();
        this.version = ASN1Integer.getInstance(localEnumeration.nextElement());
        this.digestAlgorithms = ((ASN1Set)localEnumeration.nextElement());
        this.contentInfo = ContentInfo.getInstance(localEnumeration.nextElement());
        while (localEnumeration.hasMoreElements())
        {
            ASN1Primitive localASN1Primitive = (ASN1Primitive)localEnumeration.nextElement();
            if (localASN1Primitive instanceof ASN1TaggedObject)
            {
                ASN1TaggedObject localASN1TaggedObject = (ASN1TaggedObject)localASN1Primitive;
                switch (localASN1TaggedObject.getTagNo())
                {
                    case 0:
                        this.certsBer = localASN1TaggedObject instanceof BERTaggedObject;
                        this.certificates = ASN1Set.getInstance(localASN1TaggedObject, false);
                        break;
                    case 1:
                        this.crlsBer = localASN1TaggedObject instanceof BERTaggedObject;
                        this.crls = ASN1Set.getInstance(localASN1TaggedObject, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value " + localASN1TaggedObject.getTagNo());
                }
            }
            else
            {
                this.signerInfos = ((ASN1Set)localASN1Primitive);
            }
        }
    }

    public ASN1Integer getVersion()
    {
        return this.version;
    }

    public ASN1Set getDigestAlgorithms()
    {
        return this.digestAlgorithms;
    }

    public ContentInfo getEncapContentInfo()
    {
        return this.contentInfo;
    }

    public ASN1Set getCertificates()
    {
        return this.certificates;
    }

    public ASN1Set getCRLs()
    {
        return this.crls;
    }

    public ASN1Set getSignerInfos()
    {
        return this.signerInfos;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector localASN1EncodableVector = new ASN1EncodableVector();
        localASN1EncodableVector.add(this.version);
        localASN1EncodableVector.add(this.digestAlgorithms);
        localASN1EncodableVector.add(this.contentInfo);
        if (this.certificates != null)
            if (this.certsBer)
                localASN1EncodableVector.add(new BERTaggedObject(false, 0, this.certificates));
            else
                localASN1EncodableVector.add(new DERTaggedObject(false, 0, this.certificates));
        if (this.crls != null)
            if (this.crlsBer)
                localASN1EncodableVector.add(new BERTaggedObject(false, 1, this.crls));
            else
                localASN1EncodableVector.add(new DERTaggedObject(false, 1, this.crls));
        localASN1EncodableVector.add(this.signerInfos);
        return new BERSequence(localASN1EncodableVector);
    }
}
