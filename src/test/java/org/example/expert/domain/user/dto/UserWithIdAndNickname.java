package org.example.expert.domain.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserWithIdAndNickname {

    private long id;
    private String nickname;
}
