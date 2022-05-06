package net.godaa.AuthenticationSpring.security.refreshToken;

import lombok.Data;
import net.godaa.AuthenticationSpring.models.User;

import javax.persistence.*;
import java.time.Instant;
@Data
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;
    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id")
    private User user;
    @Column(nullable = false, unique = true)
    private String token;
    @Column(nullable = false)
    private Instant expiryDate;
}
