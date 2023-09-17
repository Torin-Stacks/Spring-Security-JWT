package com.torin.springsecurityjwt.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "A1E9C3862A1E3C798F9F2343F8A58";
    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public <T> T extractClaim(String jwttokken, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(jwttokken);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
        return Jwts.
                builder().
                setClaims(extraClaims).
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date(System.currentTimeMillis())).
                setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 *24)).
                signWith(getSignInKey(), SignatureAlgorithm.HS256).
                compact();
    }

    public boolean isTokenValid(String jwttokken, UserDetails userDetails){
        final String username = extractUsername(jwttokken);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(jwttokken));
    }

    private boolean isTokenExpired(String jwttokken) {
        return extractExpiration(jwttokken).before(new Date());
    }

    private Date extractExpiration(String jwttokken) {
        return extractClaim(jwttokken,Claims::getExpiration);
    }

    private Claims extractAllClaims(String jwtToken){
        return Jwts.parserBuilder().
                setSigningKey(getSignInKey()).
                build().
                parseClaimsJws(jwtToken).
                getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
