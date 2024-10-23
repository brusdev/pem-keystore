package de.dentrassi.crypto.pem;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PemReader extends BufferedReader {
   private static final String BEGIN = "-----BEGIN ";
   private static final String CERTIFICATE = "CERTIFICATE";
   private static final String RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
   private static final String PRIVATE_KEY = "PRIVATE KEY";
   private static final String END = "-----END ";
   private static final List<String> KEY_ALGORITHMS = Arrays.asList("RSA", "DSA", "EC");

   private static List<KeyFactory> keyFactories;

   private static List<KeyFactory> getKeyFactories() {
      if (keyFactories == null) {
         keyFactories = new ArrayList<>();

         KEY_ALGORITHMS.forEach(s -> {
            try {
               keyFactories.add(KeyFactory.getInstance(s));
            } catch (Exception e) {
               e.printStackTrace();
            }
         });
      }

      return keyFactories;
   }

   public PemReader(Reader in) {
      super(in);
   }


   public Object readObject() throws CertificateException, IOException {
      byte[] objectContent = null;
      String objectType = null;

      String line = readLine();

      while (line != null && !line.startsWith(BEGIN)) {
         line = readLine();
      }

      if (line != null) {
         line = line.substring(BEGIN.length()).trim();
         int index = line.indexOf('-');

         if (index > 0 && line.endsWith("-----") && (line.length() - index) == 5) {
            objectType = line.substring(0, index);

            StringBuffer buffer = new StringBuffer();
            String endMarker = END + objectType + "-----";
            while ((line = readLine()) != null && line.indexOf(endMarker) != 0) {
               if (line.indexOf(':') < 0) {
                  buffer.append(line.trim());
               }
            }
            objectContent = java.util.Base64.getDecoder().decode(buffer.toString());
         }
      }

      if (objectContent != null)
      {
         if (CERTIFICATE.equals(objectType)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            try (ByteArrayInputStream contentInputStream = new ByteArrayInputStream(objectContent)) {
               return certificateFactory.generateCertificate(contentInputStream);
            }
         } else if (RSA_PRIVATE_KEY.equals(objectType)) {
            List<BigInteger> keyFields = new ArrayList<>();
            try (ByteArrayInputStream in = new ByteArrayInputStream(objectContent)) {
               int sequenceTag = in.read();
               if (sequenceTag == -1)
                  throw new IOException("Invalid sequence tag");
               int sequenceType = sequenceTag & 0x1F;
               if (sequenceType != 0x10)
                  throw new IOException("Invalid sequence type");
               int sequenceLength = in.read();
               if ((sequenceLength & ~0x7F) != 0) {
                  byte[] sequenceLengthBytes = new byte[sequenceLength & 0x7F];
                  if (in.read(sequenceLengthBytes) < (sequenceLength & 0x7F))
                     throw new IOException("Invalid sequence length stream");
                  sequenceLength = new BigInteger(1, sequenceLengthBytes).intValue();
               }
               if (in.available() < sequenceLength)
                  throw new IOException("Invalid sequence stream");

               for (int i = 0; i < 9; i++) {
                  int integerTag = in.read();
                  if (integerTag == -1)
                     throw new IOException("Invalid integer tag");
                  int integerType = integerTag & 0x1F;
                  if (integerType != 0x02)
                     throw new IOException("Invalid integer type");
                  int integerLength = in.read();
                  if ((integerLength & ~0x7F) != 0) {
                     byte[] integerLengthBytes = new byte[integerLength & 0x7F];
                     if (in.read(integerLengthBytes) < (integerLength & 0x7F))
                        throw new IOException("Invalid sequence length stream");
                     integerLength = new BigInteger(1, integerLengthBytes).intValue();
                  }
                  byte[] integerBytes = new byte[integerLength];
                  if (in.read(integerBytes) < integerLength)
                     throw new IOException("Invalid integer stream");

                  keyFields.add(new BigInteger(integerBytes));
               }
            }

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(keyFields.get(1), keyFields.get(2), keyFields.get(3),
               keyFields.get(4), keyFields.get(5), keyFields.get(6), keyFields.get(7), keyFields.get(8));
            try {
               KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
               return rsaKeyFactory.generatePrivate(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
               throw new IOException(e);
            }
         } else if (PRIVATE_KEY.equals(objectType)) {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(objectContent);

            InvalidKeySpecException firstException = null;
            for (KeyFactory factory : getKeyFactories()) {
               try {
                  return factory.generatePrivate(keySpec);
               } catch (InvalidKeySpecException e) {
                  if (firstException == null)
                     firstException = e;
               }
            }
            throw new IOException("Private key could not be loaded", firstException);
         } else {
            throw new IOException("Invalid object: " + objectType);
         }
      }

      return null;
   }
}
