package com.abw12.absolutefitness.authservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    @Value("${secret}")
    private String SECRET;

    public String generateToken(String appId) {
        Map<String,Object> claims = new HashMap<>();
        return createToken(claims, appId);
    }

    private String createToken(Map<String, Object> claims, String appId) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(appId)
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*30)) //30 min
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }
}


