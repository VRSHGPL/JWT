package com.vg.jwt.service;

import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JweToken {

    /** private static SecretKey secretKey; **/
    private static final long EXPIRATIONTIME = 1;
    /** private static final long EXPIRATIONTIME = 864_000_00; */
    private static final Logger LOGGER = LoggerFactory.getLogger(JweToken.class);

    static {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            // secretKey = keyGen.generateKey();

        } catch (NoSuchAlgorithmException e) {
            LOGGER.info("", e);
        }

    }

    public String jweTokenGenerator(SecretKey secretKey) {

        // https://github.com/pac4j/pac4j/issues/355
        // https://stackoverflow.com/questions/3425766/how-would-i-use-maven-to-install-the-jce-unlimited-strength-policy-files
        try {
            Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
            field.setAccessible(true);
            field.set(null, java.lang.Boolean.FALSE);
        } catch (ClassNotFoundException | NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException ex) {
            LOGGER.info("", ex);

        }

        try {

            // Step 1 : Create Payload
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("subject")
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRATIONTIME)).claim("roles", "user").claim("userId", "123")
                    .issuer("VG").build();

            // Step 2 : Sign payload with secret key
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(new MACSigner(secretKey.getEncoded()));

            // Step 3: Encrypt After Signing
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
                    new Payload(signedJWT));

            jweObject.encrypt(new DirectEncrypter(secretKey.getEncoded()));
            String jweString = jweObject.serialize();
            LOGGER.info(jweString);
            return jweString;
        } catch (JOSEException e) {
            LOGGER.info("", e);
            return null;
        }

    }

    public void jweTokenValidator(String jweString, SecretKey secretKey) {

        JWEObject jweObject;
        try {

            // Parse the JWE string
            jweObject = JWEObject.parse(jweString);

            // Decrypt with shared key
            jweObject.decrypt(new DirectDecrypter(secretKey.getEncoded()));

            // Extract payload
            SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

            signedJWT.verify(new MACVerifier(secretKey.getEncoded()));
            // signedJWT.getJWTClaimsSet().getSubject();
            LOGGER.info("Token Validated");
        } catch (ParseException | JOSEException e) {
            LOGGER.info("Validation Failed : {}", e);
            e.printStackTrace();
        }

    }

}
