package org.example.expert.domain.common.dto;

import lombok.Getter;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;

@Getter
public class AuthUser {

    private final Long id;
    private final String email;
    private Collection<? extends GrantedAuthority> authorities;
    private final String nickname;

    public AuthUser(Long id, String email, UserRole userRole, String nickname) {
        this.id = id;
        this.email = email;
        this.authorities = List.of(new SimpleGrantedAuthority(userRole.name()));
        this.nickname = nickname;
    }

    // userRole은 하나라고 가정되어 있는 현재 코드 정책
    public UserRole getUserRole() {
        String role = authorities.stream().findFirst()
                .orElseThrow(
                        () -> new InvalidRequestException("사용자 역할이 주어지지 않았습니다.")
                )
                .getAuthority();

        return UserRole.of(role);
    }
}
