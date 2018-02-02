package com.vg.controller;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.vg.jwt.service.AuthService;

@ComponentScan("com.vg")
@RestController
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @RequestMapping(value = "/auth", method = RequestMethod.GET)
    public String authenticateAPISignature(@RequestHeader(value = "Authorization", required = true) String authorization, HttpServletResponse response) {
        LOGGER.info("******************* Entering /auth **************************************");

        if (authorization == null || !authorization.startsWith("Basic ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return "UNAUTHORIZED";
        } else {
            LOGGER.info("API Auth Details :: {} ", authorization);
            // Step 1: validate API Key
        }

        // Step 2: Generate JWT
        String jwtToken = authService.jwtTokenGenerator();
        LOGGER.info("JWT Token Created :: {} ", jwtToken);
        response.addHeader("Authorization", "Bearer" + " " + jwtToken);
        response.setStatus(HttpServletResponse.SC_ACCEPTED);

        LOGGER.info("*******************  Exiting /auth *************************************");
        return "Authenticated";

    }

    @RequestMapping(value = "/other", method = RequestMethod.GET)
    public String otherEP(@RequestHeader(value = "Authorization", required = true) String authorization, HttpServletResponse response) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return "UNAUTHORIZED";
        }

        /** To strip Bearer **/
        final String token = authorization.substring(7);

        LOGGER.info("Incoming JWT Token :: {} ", token);
        try {
            authService.jwtTokenValidator(token);
        } catch (Exception e) {
            LOGGER.error("", e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return "UNAUTHORIZED";
        }
        LOGGER.info("******************* Token Validated in /other *****************************");

        return "TOKEN VALIDATED";

    }

}
