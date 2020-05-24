package com.security.demosecurity.resourse;


import io.jsonwebtoken.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtils {
   String signatureKey="HGHGHGHHG1";

   public String generateToken(UserDetails userDetails)
   {
      Map<String,Object> claims=new HashMap<>();
      return createToken(claims,userDetails);
   }

   private String createToken(Map<String,Object> claims, UserDetails userDetails) {
      return  Jwts.builder()
                  .setClaims(claims)
                  .setSubject(userDetails.getUsername())
                  .setIssuedAt(new Date(System.currentTimeMillis()))
                  .setExpiration(new Date(System.currentTimeMillis()+1000*60*60*10))
                  .signWith(SignatureAlgorithm.HS256,signatureKey)
                  .compact();
   }
   public Boolean validateToken(String token, UserDetails userDetails) {
       final String userName=extractUserName(token);
        return userName.equals(userDetails.getUsername())&& isTokenExpired(token);
   }

   public Claims parseClaims(String token)
   {
      return Jwts.parser().setSigningKey(signatureKey).parseClaimsJws(token).getBody();
   }

   private boolean isTokenExpired(String token) {

      return new Date(System.currentTimeMillis()).after(parseClaims(token).getExpiration());
   }

   public String extractUserName(String token) {

      return  parseClaims(token).getSubject();
   }
}
