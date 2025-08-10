package guddo.dto;

import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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

    @NotBlank(message = "First name is mandatory")
    private String firstname;

    private String lastname;


    @Column(unique = true, nullable = false)
    @NotBlank(message = "Email is mandatory")
    @Email(message = "Please provide a valid email address")
    private String email;

    @NotBlank(message = "Password is mandatory")
    @Size(min = 5, message = "Password must be at least 5 characters long")
    private String password;

}