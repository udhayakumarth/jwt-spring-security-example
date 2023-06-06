package com.example.jwtspringsecurity.config.user;

import com.example.jwtspringsecurity.config.jwt.JwtTokenProvider;
import com.example.jwtspringsecurity.config.token.Token;
import com.example.jwtspringsecurity.config.token.TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenRepository tokenRepository;
    @Lazy
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Lazy
    @Autowired
    private PasswordEncoder passwordEncoder;


    public boolean verifyUser(String email,String password){
        User user = userRepository.findByEmail(email).orElseThrow();
        return new BCryptPasswordEncoder().matches(password, user.getPassword());
    }

    public boolean checkUserNameExists(String email){
        return userRepository.findByEmail(email).isPresent();
    }

    public String generateToke(String email,String password){

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = tokenProvider.generateToken(authentication);
        Token saveToken = new Token();
        saveToken.setToken(token);
        tokenRepository.save(saveToken);
        return token;
    }

    public boolean createUser(User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return true;
    }
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(""));
    }
}
