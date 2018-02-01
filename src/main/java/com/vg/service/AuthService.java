package com.vg.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private static final long EXPIRATIONTIME = 864_000_00;
    // private static final long EXPIRATIONTIME = 1;
    private static final String SECRET = "SomeSecretKey";
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

    /**
     * Claims :- iss: issuer of the token exp: the expiration timestamp (reject tokens which have expired). Note: as defined in the spec, this must be
     * in seconds. iat: The time the JWT was issued. Can be used to determine the age of the JWT nbf: "not before" is a future time when the token
     * will become active. jti: unique identifier for the JWT. Used to prevent the JWT from being re-used or replayed. sub: subject of the token
     * (rarely used) aud: audience of the token (also rarely used)
     * 
     * @return
     */
    public String jwtTokenGenerator() {

        return Jwts.builder().setSubject("subject").claim("roles", "user").claim("userId", "123").setIssuedAt(new Date()).setIssuer("VG")
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME)).signWith(SignatureAlgorithm.HS256, SECRET).compact();

    }

    public void jwtTokenValidator(final String token) throws Exception {
        try {
            Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token);
        } catch (SignatureException e) {
            LOGGER.info("SignatureException : {}", e);
            throw new Exception("INVALID TOKEN");
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
            LOGGER.info("JWT Err : {}", e);
            throw new Exception("JWT VALIDATION FAILED");
        }
    }

    public void apiSignatureValidator() {

    }

}
