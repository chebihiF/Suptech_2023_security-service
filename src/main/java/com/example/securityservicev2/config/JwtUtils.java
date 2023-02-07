package com.example.securityservicev2.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import java.util.function.Function;

@Component
public class JwtUtils {

    private String jwtStringKey = "secret" ;

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims  = extarctAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extarctAllClaims(String token){
        return Jwts.parser().setSigningKey(jwtStringKey).parseClaimsJws(token).getBody();
    }
}
