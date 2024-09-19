package com.jwtauthentication.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public MyUserDetailsService(@Lazy PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Aquí deberías buscar al usuario en la base de datos. Para este ejemplo, usamos uno estático.
        if ("foo".equals(username)) {
            String encodedPassword = passwordEncoder.encode("password");
            return new org.springframework.security.core.userdetails.User("foo", encodedPassword, new ArrayList<>());
        } else {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
