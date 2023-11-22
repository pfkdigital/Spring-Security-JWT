package com.example.springsecurity.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
  @Value("${application.security.jwt.secret-key}")
  private String secretKey;

  @Value("${application.security.jwt.expiration}")
  private long jwtExpiration;

  @Value("${application.security.jwt.refresh-token.expiration}")
  private long jwtRefreshExpiration;

  private String buildToken(
      Map<String, Object> extraClaims, UserDetails userDetails, long expirationTime) {
    return Jwts.builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.getUsername())
        .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  public String generateAccessToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return buildToken(extraClaims, userDetails, jwtExpiration);
  }

  public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return buildToken(extraClaims, userDetails, jwtRefreshExpiration);
  }

  public String generateToken(UserDetails userDetails) {
    return generateAccessToken(new HashMap<>(), userDetails);
  }

  public String generateRefreshToken(UserDetails userDetails) {
    return generateRefreshToken(new HashMap<>(), userDetails);
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
    byte[] keyInBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyInBytes);
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String userName = extractUserName(token);

    return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  public boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }
}
