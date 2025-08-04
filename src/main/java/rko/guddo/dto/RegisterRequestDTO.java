package rko.guddo.dto;

import jakarta.persistence.Column;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequestDTO implements Serializable {

    private static final Long serialVersionUID = 5926468583005150707L;

    @NotBlank(message = "First is mandatory")
    private String firstname;

    private String lastname;


    @Column(unique = true, nullable = false)
    @NotBlank(message = "Email is mandatory")
    private String email;

    @NotBlank(message = "Password is mandatory")
    private String password;
}