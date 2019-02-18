package org.luoyw.easysign.sign;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.util.Enumeration;

/**
 * SM2 签名封装 ASN1
 * 按照《SM2密码算法使用规范（GM/T 0009-2012）》，签名结果为ASN.1编码：
 *       SM2Signature::= SEQUENCE {
 *          R  INTEGER,  --签名值的第一部分
 *          S  INTEGER   --签名值的第二部分
 *       }
 * @author luoyanwu
 *
 */
public class SM2Signature extends ASN1Object
{
    private ASN1Sequence sequence;  
    private ASN1Integer R; 
    private ASN1Integer S;  
    private SM2Signature(ASN1Sequence sequence) {  
        this.sequence = sequence;  
        Enumeration<Object> emu = this.sequence.getObjects();  
        R = (ASN1Integer) emu.nextElement();
        S = (ASN1Integer) emu.nextElement();  
    }  
    
    SM2Signature(ASN1Integer R,ASN1Integer S) {  
        this.R = R;
        this.S = S;  
    }  
    
    public SM2Signature(byte[] R,byte[] S) {  
        this.R = new ASN1Integer(R);
        this.S = new ASN1Integer(S);  
    } 
    
    public SM2Signature(BigInteger R,BigInteger S) {  
        this.R = new ASN1Integer(R);
        this.S = new ASN1Integer(S);  
    }  
    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(R);
        vector.add(S);
        return new DERSequence(vector);
    }

}
