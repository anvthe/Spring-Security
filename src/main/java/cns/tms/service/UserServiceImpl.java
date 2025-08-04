package cns.tms.service;

import cns.tms.domain.User;
import cns.tms.dto.UserDto;
import cns.tms.exception.UsernameAlreadyExistsException;
import cns.tms.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl {


    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public void registerUser(UserDto userDto) {
        // Check if username already exists
        if (userRepository.existsByUsername(userDto.getUsername())) {
            throw new UsernameAlreadyExistsException("Username is already registered");
        }

        // Create new User entity
        User user = new User();
        user.setUsername(userDto.getUsername());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setEmail(userDto.getEmail());
        // Set other fields from userDto if needed

        // Save to database
        userRepository.save(user);
    }
}
