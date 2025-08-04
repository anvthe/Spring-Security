package rko.guddo.service;

import rko.guddo.domain.User;
import rko.guddo.domain.enums.Role;
import rko.guddo.dto.AuthenticationRequestDTO;
import rko.guddo.dto.RegisterRequestDTO;
import rko.guddo.dto.TokenRefreshDTO;
import rko.guddo.dto.UpdatePasswordRequestDTO;
import rko.guddo.exception.EmailAlreadyExistsException;
import rko.guddo.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    //registration
    public void register(RegisterRequestDTO request) {

        // Check if email already exists
        if (repository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email address already registered!");
        }

        // Build and save new user
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
    }



    //login
    public String authenticate(@Valid AuthenticationRequestDTO request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),
                request.getPassword()));
        try {
            var user = repository.findByEmail(request.getEmail()).orElseThrow();
            return jwtService.generateToken(user);
        } catch (UsernameNotFoundException usernameNotFoundException) {
            return usernameNotFoundException.getMessage();
        }
    }

    //update password
    @Transactional
    public void updatePassword(UpdatePasswordRequestDTO request) {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = repository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Email not found"));
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Old password is incorrect");
        }
        if (!request.passwordsMatch()) {
            throw new RuntimeException("New password and confirm password do not match");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        repository.save(user);
    }

    //refresh token
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authHeader = request.getHeader("Authorization");
        String refreshToken;
        String email;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            refreshToken = authHeader.substring(7);
            email = jwtService.extractEmail(refreshToken);

            if (email != null) {
                var user = repository.findByEmail(email).orElseThrow(
                        () -> new UsernameNotFoundException("User not found")
                );

                if (jwtService.isTokenValid(refreshToken, user)) {
                    String newAccessToken = jwtService.generateToken(user);
                    TokenRefreshDTO tokenResponse = TokenRefreshDTO.builder()
                            .accessToken(newAccessToken)
                            .refreshToken(refreshToken)
                            .build();

                    response.setContentType("application/json");
                    new ObjectMapper().writeValue(response.getOutputStream(), tokenResponse);
                } else {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("Invalid refresh token");
                }
            }
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Refresh token is missing");
        }
    }
}