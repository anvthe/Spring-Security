package guddo.controller;

import guddo.WebApiUrlConstants.WebApiUrlConstants;
import guddo.dto.AuthenticationRequestDTO;
import guddo.dto.RegisterRequestDTO;
import guddo.dto.UpdatePasswordRequestDTO;
import guddo.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    //registration
    //@PreAuthorize("hasRole('ADMIN')")

    @PostMapping(WebApiUrlConstants.USER_REGISTER_API)
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequestDTO request) {

        service.register(request);
        return ResponseEntity.ok("User created successfully");
    }

    //login
    @PostMapping(WebApiUrlConstants.USER_LOGIN_API)
    public ResponseEntity<?> authenticate(@RequestBody @Valid AuthenticationRequestDTO request) {
        return ResponseEntity.ok(service.authenticate(request));
    }


    //update password
    @PutMapping(WebApiUrlConstants.USER_UPDATE_PASSWORD_API)
    public ResponseEntity<?> updatePassword(@RequestBody @Valid UpdatePasswordRequestDTO request) {

        service.updatePassword(request);
        return ResponseEntity.ok("Password updated successfully");
    }


    //refresh token
    @PostMapping(WebApiUrlConstants.USER_REFRESH_TOKEN_API)
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        service.refreshToken(request, response);
    }
}