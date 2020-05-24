package com.security.demosecurity.security;


import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class MyUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        if(s.equals("demo")) {
            return new User("demo", "demo", new ArrayList<>());
        }
        else
        {
            throw  new UsernameNotFoundException("User Not Found");
        }

    }
}
