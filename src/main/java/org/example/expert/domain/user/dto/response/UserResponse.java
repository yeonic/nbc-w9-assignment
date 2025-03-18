package org.example.expert.domain.user.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;
import org.example.expert.domain.user.entity.User;

@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserResponse {

    private final Long id;
    private final String email;
    private final String nickname;
    private String profileImgUrl;

    public UserResponse(Long id, String email, String nickname) {
        this.id = id;
        this.email = email;
        this.nickname = nickname;
    }

    @Builder
    private UserResponse(Long id, String email, String nickname, String profileImgUrl) {
        this.id = id;
        this.email = email;
        this.nickname = nickname;
        this.profileImgUrl = profileImgUrl;
    }

    public static UserResponse fromUser(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .nickname(user.getNickname())
                .profileImgUrl(user.getProfileImgUrl() != null ? user.getProfileImgUrl() : "")
                .build();
    }
}
