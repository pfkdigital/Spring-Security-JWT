package com.example.springsecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
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
  private static final String SECRET_KEY =
      "52F4278EA4EFB23F2D5C434701D0C31BD3CF67E2C7D9D876851706AB1B0689B5";

  private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setExpiration(new Date(System.currentTimeMillis() * 1000 * 60 * 24))
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  private Claims extractAllClaims(String token) {
    JwtParser parser = Jwts.parserBuilder().setSigningKey(getSignInKey()).build();
    return parser.parseClaimsJws(token).getBody();
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public String extractUserName(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  private Key getSignInKey() {
    byte[] keyInBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyInBytes);
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String userName = extractUserName(token);

    return (userName.equals(userDetails.getUsername())) && !isTokenValid(token);
  }

  public boolean isTokenValid(String token) {
    return extractExpiration(token).before(new Date());
  }
}
