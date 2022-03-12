package net.godaa.AuthenticationSpring.registration;

import lombok.AllArgsConstructor;
import net.godaa.AuthenticationSpring.Email.EmailSender;
import net.godaa.AuthenticationSpring.Email.EmailService;
import net.godaa.AuthenticationSpring.enumeration.AppUserRole;
import net.godaa.AuthenticationSpring.registration.token.ConfirmationToken;
import net.godaa.AuthenticationSpring.registration.token.ConfirmationTokenService;
import net.godaa.AuthenticationSpring.user.User;
import net.godaa.AuthenticationSpring.user.UserService;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class RegistrationService {
//    define all services
    private final UserService userService;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmationTokenService;
    private final EmailSender emailSender;

    public String register(RegistrationRequest request) {
        boolean isValidEmail = emailValidator.test(request.getEmail());
        if (!isValidEmail) {
            throw new IllegalStateException("email not valid");
        }
        String token =  userService.signUpUser(new User(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                request.getPassword(),
                AppUserRole.USER


        ));
//        emailSender.senEmail(request.getEmail(),);
        return token;

    }

    @Transactional
    public String confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenService
                .getToken(token)
                .orElseThrow(() ->
                        new IllegalStateException("token not found"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("email already confirmed");
        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("token expired");
        }

        confirmationTokenService.setConfirmedAt(token);
        userService.enableUser(confirmationToken.getUser().getEmail());
        return "confirmed";
    }

}
