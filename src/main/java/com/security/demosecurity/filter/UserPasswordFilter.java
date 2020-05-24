package com.security.demosecurity.filter;

import com.security.demosecurity.resourse.JwtUtils;
import com.security.demosecurity.security.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.function.Predicate;

@Component
public class UserPasswordFilter extends OncePerRequestFilter {
    private Predicate<String> stringPredicate=s->s.startsWith("Bearer");

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        Optional<String> jwtToken=Optional.empty();
        Optional<String> jwtHeader=Optional.ofNullable(httpServletRequest.getHeader("Authorization"));
        if(jwtHeader.isPresent())
         jwtToken=jwtHeader.filter(stringPredicate).map(s ->s.substring(7));
        Optional<String> userName=Optional.empty();
        if(jwtToken.isPresent())
        {
            userName=Optional.of(jwtUtils.extractUserName(jwtToken.get()));
        }
        Optional<Authentication> authentication=Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication());
        if(userName.isPresent() && !authentication.isPresent())
        {
            UserDetails userDetails=myUserDetailService.loadUserByUsername(userName.get());
            if(jwtUtils.validateToken(jwtToken.get(),userDetails));
            {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }

        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

}
