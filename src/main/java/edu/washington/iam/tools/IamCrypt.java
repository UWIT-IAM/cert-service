/* ========================================================================
 * Copyright (c) 2010-2011 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/* ian crypt utils */

package edu.washington.iam.tools;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.security.Key;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class IamCrypt {

  private static String cryptKey;
  private static MessageDigest messageDigest;
  private static Key key;
  private static Cipher cipher;
  private static Base64 b64;
  private static Logger log =  LoggerFactory.getLogger(IamCrypt.class);
  private final static  String MDAlgorithm = "MD5";

  public static void init(String secretKey) {
     cryptKey = secretKey;
     b64 = new Base64();
     String key16 = secretKey + "xxxxxxxxxxxxxxxxxxxxxxx";
     try {
        key = new SecretKeySpec(key16.getBytes(), 0, 16, "AES");
        cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        messageDigest = MessageDigest.getInstance("SHA-1");
     } catch (NoSuchAlgorithmException e) {
        log.error("no algorithm? " + e);
     } catch (NoSuchProviderException e) {
        log.error("no BC? " + e);
     } catch (NoSuchPaddingException e) {
        log.error("no BC? " + e);
     }
  }

  public static synchronized String genMD(String in) {
     messageDigest.reset();
     byte[] bt = in.getBytes();
     // messageDigest.update(bt);
     String md = new String( b64.encode(messageDigest.digest(bt)));
     // log.debug("md of " + in + " = " + md);
     messageDigest.reset();
     return (md);
  }

  public static synchronized String encode(String in) {
     byte[] bt = in.getBytes();
     try {
        cipher.init(Cipher.ENCRYPT_MODE, key);
        String out = new String(b64.encode(cipher.doFinal(bt)));
        // log.debug("encode: " + in + " to " + out);
        return out;
     } catch (InvalidKeyException e) {
        log.error("encode: " + e);
        return null;
     } catch (IllegalBlockSizeException e) {
        log.error("encode: " + e);
        return null;
     } catch (BadPaddingException e) {
        log.error("encode: " + e);
        return null;
     }
  }

  public static synchronized String decode(String in) {
     byte[] inb = b64.decode(in);
     try {
        cipher.init(Cipher.DECRYPT_MODE, key);
        String out = new String(cipher.doFinal(inb));
        // log.debug("decode: " + in + " to " + out);
        return out;
     } catch (InvalidKeyException e) {
        log.error("encode: " + e);
        return null;
     } catch (IllegalBlockSizeException e) {
        log.error("encode: " + e);
        return null;
     } catch (BadPaddingException e) {
        log.error("encode: " + e);
        return null;
     }
  }

}

