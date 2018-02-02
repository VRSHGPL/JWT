package com.vg.jwt;

import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vg.jwt.service.JweToken;

@RunWith(SpringRunner.class)
@SpringBootTest
public class JwtTest {
    private RestTemplate restTemplate = new RestTemplate();
    String uri = "http://localhost:8080/auth";

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtTest.class);

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Autowired
    private JweToken jweToken;

    @Test
    public void callEPPositive() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", "Basic dummy_apiKey" + ":" + "dummy_signature" + ":" + "43124324141242");

        HttpEntity<String> requestEntity = new HttpEntity<String>(null, headers);
        String auth = "http://localhost:8080/auth";
        ResponseEntity<String> entity = restTemplate.exchange(auth, HttpMethod.GET, requestEntity, String.class);
        LOGGER.info("entity.getStatusCode() : {}", entity.getStatusCode());
        LOGGER.info("entity.getHeaders() : {}", entity.getHeaders());

        HttpEntity<String> requestEntitywithToken = new HttpEntity<String>(null, entity.getHeaders());
        String otherEP = "http://localhost:8080/other";
        ResponseEntity<String> entitys = restTemplate.exchange(otherEP, HttpMethod.GET, requestEntitywithToken, String.class);
        LOGGER.info("entitys.getStatusCode() : {}", entitys.getStatusCode());
        LOGGER.info("entitys : {}", entitys);

    }

    @Test
    public void callEPNegative() {
        thrown.expect(HttpClientErrorException.class);
        thrown.expectMessage("401");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", "Basic dummy_apiKey" + ":" + "dummy_signature" + ":" + "43124324141242");

        HttpEntity<String> requestEntity = new HttpEntity<String>(null, headers);
        String auth = "http://localhost:8080/auth";
        ResponseEntity<String> entity = restTemplate.exchange(auth, HttpMethod.GET, requestEntity, String.class);
        LOGGER.info("entity.getStatusCode() : {}", entity.getStatusCode());
        LOGGER.info("entity.getHeaders() : {}", entity.getHeaders());

        LOGGER.info("Token in Test :: {}", entity.getHeaders().getFirst("Authorization"));

        String[] tokenArrr = entity.getHeaders().getFirst("Authorization").split("\\.");
        String corruptedToken = tokenArrr[0] + "." + tokenArrr[1] + "junk" + "." + tokenArrr[2];

        HttpHeaders corruptedHeader = new HttpHeaders();
        corruptedHeader.setContentType(MediaType.APPLICATION_JSON);
        corruptedHeader.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        corruptedHeader.set("Authorization", corruptedToken);

        HttpEntity<String> requestEntitywithToken = new HttpEntity<String>(null, corruptedHeader);
        String otherEP = "http://localhost:8080/other";
        ResponseEntity<String> entitys = restTemplate.exchange(otherEP, HttpMethod.GET, requestEntitywithToken, String.class);
        LOGGER.info("entitys.getStatusCode() : {}", entitys.getStatusCode());
        LOGGER.info("entitys : {}", entitys);
    }

    @Test
    public void jweTokenGenerator() {

        KeyGenerator keyGen;
        SecretKey secretKey;

        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            secretKey = keyGen.generateKey();

            String token = jweToken.jweTokenGenerator(secretKey);

            // validate token
            jweToken.jweTokenValidator(token, secretKey);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @Test
    public void jweCode() {
        try {

            try {
                Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
                field.setAccessible(true);
                field.set(null, java.lang.Boolean.FALSE);
            } catch (ClassNotFoundException | NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException ex) {
                ex.printStackTrace(System.err);
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();

            LOGGER.info("=====================================================");
            LOGGER.info("secretKey.getEncoded() : {}", secretKey.getEncoded());

            // Create HMAC signer
            JWSSigner signer = new MACSigner(secretKey.getEncoded());

            // Prepare JWT with claims set
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("subject").expirationTime(new Date(System.currentTimeMillis()))
                    .claim("roles", "user").claim("userId", "123").issuer("VG").build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

            // Apply the HMAC
            signedJWT.sign(signer);

            // Testing signing
            // String s = signedJWT.serialize();
            // signedJWT = SignedJWT.parse(s);
            // JWSVerifier verifier = new MACVerifier(secretKey.getEncoded());
            // LOGGER.info(signedJWT.verify(verifier));
            // LOGGER.info("***********************************************************************************");

            // Create JWE object with signed JWT as payload
            JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT") // required to
                                                                                                                                     // signal nested
                                                                                                                                     // JWT
                    .build(), new Payload(signedJWT));

            // Perform encryption
            jweObject.encrypt(new DirectEncrypter(secretKey.getEncoded()));

            // Serialise to JWE compact form
            String jweString = jweObject.serialize();
            LOGGER.info(jweString);
        } catch (NoSuchAlgorithmException | JOSEException e) {
            e.printStackTrace();
        }
    }
}
