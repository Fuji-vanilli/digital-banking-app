package org.sid.ebankingbackend.sercurity;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
public class SecurityController {
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @GetMapping("profile")
    public Authentication profile(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @PostMapping("login")
    public Map<String, String> login(String username, String password){
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));

        return Map.of(
                "access-token", jwtService.generateJwt(authentication, username)
        );
    }
}
