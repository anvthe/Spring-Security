package guddo.service;

import guddo.domain.User;
import guddo.domain.enums.Role;
import guddo.dto.*;
import guddo.exception.EmailAlreadyExistsException;
import guddo.repository.UserRepository;
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
        // Get the logged-in user's email
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        // Find the user by email
        User user = repository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found by email"));

        // Validate current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new RuntimeException("Old password is incorrect");
        }

        // Validate new + confirm match
        if (!request.passwordsMatch()) {
            throw new RuntimeException("New password and confirm password do not match");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        repository.save(user);
    }



    //refresh token
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authHeader = request.getHeader("Authorization");
        String refreshToken;
        String userEmail;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            refreshToken = authHeader.substring(7);
            userEmail = jwtService.extractUsername(refreshToken);

            if (userEmail != null) {
                var user = repository.findByEmail(userEmail).orElseThrow(
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