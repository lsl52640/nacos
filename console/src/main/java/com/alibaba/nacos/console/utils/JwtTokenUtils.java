/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.nacos.console.utils;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;
import java.util.List;
import java.util.Map;


/**
 * Jwt token tool
 *
 * @author wfnuser
 */
@Component
public class JwtTokenUtils {

    private final Logger log = LoggerFactory.getLogger(JwtTokenUtils.class);

    private static final String AUTHORITIES_KEY = "auth";

    /**
     * secret key
     */
    private String secretKey;

    /**
     * Token validity time(ms)
     */
    private long tokenValidityInMilliseconds;
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    @Value("#{${nacos-key}}")
    private Map<String, String> appKey;


    @PostConstruct
    public void init() {
        this.secretKey = "SecretKey012345678901234567890123456789012345678901234567890123456789";
        this.tokenValidityInMilliseconds = 1000 * 60 * 30L;
    }

    public String getKey(String app){
        return appKey.get(app);
    }

    /**
     * Create token
     *
     * @param authentication auth info
     * @return token
     */
    public String createToken(Authentication authentication) {
        /**
         * Current time
         */
        long now = (new Date()).getTime();
        /**
         * Validity date
         */
        Date validity;
        validity = new Date(now + this.tokenValidityInMilliseconds);

        /**
         * create token
         */
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, "")
                .setExpiration(validity)
                .signWith(generalKey(), signatureAlgorithm)
                .compact();
    }

    /**
     * Get auth Info
     *
     * @param token token
     * @return auth info
     */
    public Authentication getAuthentication(String token) {
        /**
         *  parse the payload of token
         */
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();

        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get(AUTHORITIES_KEY));


        User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    /**
     * validate token
     *
     * @param token token
     * @return whether valid
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature.");
            log.trace("Invalid JWT signature trace: {}", e);
        } catch (MalformedJwtException e) {
            log.info("Invalid JWT token.");
            log.trace("Invalid JWT token trace: {}", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT token.");
            log.trace("Expired JWT token trace: {}", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT token.");
            log.trace("Unsupported JWT token trace: {}", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT token compact of handler are invalid.");
            log.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

    public SecretKey generalKey() {
        SecretKey key = new SecretKeySpec(secretKey.getBytes(), 0, secretKey.length(), "AES");
        return key;
    }

}
