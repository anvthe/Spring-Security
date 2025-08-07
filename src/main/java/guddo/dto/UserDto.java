package guddo.dto;

import jakarta.persistence.Column;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

    @Column(unique = true)
    @NotBlank(message = "Email must be")
    private String email;

    @NotBlank(message = "Password must be")
    private String password;


}