package org.luoyw.easysign.sign;

import java.math.BigInteger;
import java.util.Arrays;

public class BigIntegerUtil
{
    //首位小于0 部0
  public static BigInteger toPositiveInteger(byte[] in)
  {
    if (in == null)
      return null;
    byte[] bt = (byte[])null;
    if (in[0] < 0) {
      bt = new byte[in.length + 1];
      bt[0] = 0;
      System.arraycopy(in, 0, bt, 1, bt.length - 1);
    } else {
      bt = in;
    }
    return new BigInteger(bt);
  }

  public static byte[] asUnsigned32ByteArray(BigInteger n) {
    return asUnsignedNByteArray(n, 32);
  }

  public static byte[] asUnsignedNByteArray(BigInteger x, int length) {
    if (x == null)
      return null;
    byte[] tmp = new byte[length];
    byte[] arrays = x.toByteArray();
    int len = arrays.length;
    if (len > length + 1)
      return null;
    if (len == length + 1) {
      if (arrays[0] != 0)
        return null;

      System.arraycopy(arrays, 1, tmp, 0, length);
      return tmp;
    }

    System.arraycopy(arrays, 0, tmp, length - len, len);
    return tmp;
  }
  
  
  public  static  void main(String dfd[]){
      BigInteger bigInteger=  new BigInteger("109730442400816954224298342227686375833309693139865437595296827559949801446395");
      byte[] bytee = asUnsigned32ByteArray(bigInteger);
      System.out.println(Arrays.toString(bigInteger.toByteArray()));
      System.out.println(Arrays.toString(bytee));
      System.out.println("#"+toPositiveInteger(bytee));

      
      BigInteger arrayOfBigInteger2 = new BigInteger(bytee);
      System.out.println(arrayOfBigInteger2);
      
  }
}