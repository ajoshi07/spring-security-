package com.security.demosecurity.resourse;

import com.security.demosecurity.security.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Supplier;

@RestController
public class SecurityResourse {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
     private MyUserDetailService userDetailService;
     private Supplier<BadCredentialsException> throwableSupplier=()->new BadCredentialsException("Bad REquest");

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping(value = "/hello")
    public ResponseEntity<String> getString(@RequestParam String name)
    {
        return new ResponseEntity<>(name,HttpStatus.BAD_GATEWAY);
    }
    @PostMapping(value = "/{name}/hi")
    public ResponseEntity<String> greet(@PathVariable String name)
    {
        return new ResponseEntity<>(name,HttpStatus.CREATED);
    }

    @PostMapping(value = "/authenticate")
    public ResponseEntity<AuthResponse> getAuthToken(@RequestHeader HttpHeaders headers) {
         Optional.ofNullable(headers).orElseThrow(throwableSupplier);
         Optional<String> userName=Optional.of(headers.get("user").stream().findFirst().get());
         Optional<String> password=Optional.of(headers.get("password").stream().findFirst().get());
        userName.orElseThrow(throwableSupplier);
        password.orElseThrow(throwableSupplier);
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userName.get(),password.get(),new ArrayList<>()));
        }catch (BadCredentialsException e)
        {
            throw new UsernameNotFoundException("User Not Found",e);
        }
        UserDetails userDetails=userDetailService.loadUserByUsername(userName.get());

        AuthResponse authResponse=new AuthResponse();
        authResponse.setAuthToken(jwtUtils.generateToken(userDetails));

        return new ResponseEntity<>(authResponse ,HttpStatus.OK);
    }
}
