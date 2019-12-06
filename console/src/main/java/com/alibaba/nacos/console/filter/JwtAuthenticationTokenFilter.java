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
package com.alibaba.nacos.console.filter;

import com.alibaba.nacos.client.config.impl.SpasAdapter;
import com.alibaba.nacos.config.server.model.User;
import com.alibaba.nacos.console.config.WebSecurityConfig;
import com.alibaba.nacos.console.security.CustomUserDetails;
import com.alibaba.nacos.console.utils.JwtTokenUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * jwt auth token filter
 *
 * @author wfnuser
 */
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private static final String TOKEN_PREFIX = "Bearer ";

    private JwtTokenUtils tokenProvider;
    private Map<String, String> appKey;

    public JwtAuthenticationTokenFilter(JwtTokenUtils tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String jwt = resolveToken(request);

        if (jwt != null && !"".equals(jwt.trim()) && SecurityContextHolder.getContext().getAuthentication() == null) {
            if (this.tokenProvider.validateToken(jwt)) {
                /**
                 * get auth info
                 */
                Authentication authentication = this.tokenProvider.getAuthentication(jwt);
                /**
                 * save user info to securityContext
                 */
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        String signature = request.getHeader("Spas-Signature");
        if (StringUtils.hasText(signature)) {
            String data = request.getHeader("Timestamp");
            String app = request.getHeader("Spas-AccessKey");
            String s = SpasAdapter.signWithhmacSHA1Encrypt(data, tokenProvider.getKey(app));
            if (s.equals(signature)) {
                User user = new User();
                user.setUsername("admin");
                CustomUserDetails customUserDetails = new CustomUserDetails(user);
                Authentication authentication = new UsernamePasswordAuthenticationToken(customUserDetails, "");
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }

    /**
     * Get token from header
     */
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(WebSecurityConfig.AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(7, bearerToken.length());
        }
        String jwt = request.getParameter(WebSecurityConfig.AUTHORIZATION_TOKEN);
        if (StringUtils.hasText(jwt)) {
            return jwt;
        }
        return null;
    }
}
