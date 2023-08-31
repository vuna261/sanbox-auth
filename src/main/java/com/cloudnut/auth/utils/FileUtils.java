package com.cloudnut.auth.utils;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class FileUtils {
    private FileUtils() {}

    /**
     * get public key from filename
     * @param filename
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getPublicKeyFromFile(String filename) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        Resource resource = new ClassPathResource(filename);
        InputStream inputStream = resource.getInputStream();

        byte[] bytesData = FileCopyUtils.copyToByteArray(inputStream);

        String publicContent = new String(bytesData, StandardCharsets.UTF_8);

        publicContent = publicContent.replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicContent));
        PublicKey publicKey = kf.generatePublic(keySpecX509);
        return publicKey;
    }

    /**
     * get private key from file
     * @param filename
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey getPrivateKeyFromFile(String filename) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        Resource resource = new ClassPathResource(filename);
        InputStream inputStream = resource.getInputStream();

        byte[] bytesData = FileCopyUtils.copyToByteArray(inputStream);

        String privateContent = new String(bytesData, StandardCharsets.UTF_8);
        privateContent = privateContent.replaceAll("\\n", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateContent));
        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);
        return privateKey;
    }
}
