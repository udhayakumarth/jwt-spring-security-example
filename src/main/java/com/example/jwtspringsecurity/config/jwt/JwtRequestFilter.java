package com.example.jwtspringsecurity.config.jwt;

import com.example.jwtspringsecurity.config.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {


    @Autowired
    private JwtTokenProvider tokenGenerator;
    private final UserService userService;

    @Autowired
    JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    public JwtRequestFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = null;
        try {
            token = getJWTFromRequest(request);
            if(token!=null){
                if(tokenGenerator.validateToken(token)) {
                    String username = tokenGenerator.getUsernameFromToken(token);
                    UserDetails userDetails = userService.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null,
                            userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            jwtAuthenticationEntryPoint.commence(request,response,e);
        }

    }

    private String getJWTFromRequest(HttpServletRequest request) {
        try {
            String bearerToken = request.getHeader("Authorization");
            return bearerToken.substring(7);
        }catch (Exception e){
            System.out.println(e.getMessage());
        }
        return null;
    }
}
