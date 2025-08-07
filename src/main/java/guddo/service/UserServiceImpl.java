package guddo.service;

import guddo.domain.User;
import guddo.dto.RegisterRequestDTO;
import guddo.exception.EmailAlreadyExistsException;

import guddo.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl {


    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public void registerUser(RegisterRequestDTO userDto) {

        // Check if email already exists
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new EmailAlreadyExistsException("Email is already registered");
        }

        // Create new User entity
        User user = new User();
        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));


        // Save to database
        userRepository.save(user);
    }
}
