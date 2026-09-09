package com.ankit.SpringSeEx.service;

import com.ankit.SpringSeEx.model.UserPrincipal;
import com.ankit.SpringSeEx.model.Users;
import com.ankit.SpringSeEx.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepo repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users user = repo.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }


        return new UserPrincipal(user);
    }
}