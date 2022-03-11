package net.godaa.AuthenticationSpring.registration;

import net.godaa.AuthenticationSpring.registration.RegistrationRequest;
import org.springframework.stereotype.Service;

@Service
public class RegistrationService {
    public String register(RegistrationRequest request) {

        return "works";
    }

}
