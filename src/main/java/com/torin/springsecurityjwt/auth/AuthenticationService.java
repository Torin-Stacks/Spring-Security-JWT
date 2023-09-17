package com.torin.springsecurityjwt.auth;

import com.torin.springsecurityjwt.config.JwtService;
import com.torin.springsecurityjwt.user.Role;
import com.torin.springsecurityjwt.user.User;
import com.torin.springsecurityjwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@RequiredArgsConstructor
public class AuthenticationService {


    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        User newUser = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(newUser);

        var jwtToken = jwtService.generateToken(newUser);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();


    }

    public AuthenticationResponse authenticate(AuthenticationRequest registerRequest) {
  authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
                  registerRequest.getEmail(),
                  registerRequest.getPassword()
          )
  );
  var user = userRepository.findByEmail(registerRequest.getEmail()).orElseThrow(()-> new UsernameNotFoundException("username not found"));
  var jwtToken = jwtService.generateToken(user);
  return AuthenticationResponse.builder()
          .token(jwtToken)
          .build();
    }
}
