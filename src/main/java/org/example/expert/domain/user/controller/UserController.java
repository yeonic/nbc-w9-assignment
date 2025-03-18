package org.example.expert.domain.user.controller;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.dto.request.UserChangePasswordRequest;
import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.service.UserS3Service;
import org.example.expert.domain.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

import static org.example.expert.domain.user.enums.UserRole.Authority.ROLE_ADMIN;
import static org.example.expert.domain.user.enums.UserRole.Authority.ROLE_USER;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final UserS3Service userS3Service;

    @GetMapping("/users/{userId}")
    public ResponseEntity<UserResponse> getUser(@PathVariable long userId) {
        return ResponseEntity.ok(userService.getUser(userId));
    }

    @Secured({ROLE_USER, ROLE_ADMIN})
    @PutMapping("/users")
    public void changePassword(@AuthenticationPrincipal AuthUser authUser,
                               @RequestBody UserChangePasswordRequest userChangePasswordRequest) {
        userService.changePassword(authUser.getId(), userChangePasswordRequest);
    }

    @Secured({ROLE_USER, ROLE_ADMIN})
    @PutMapping("/users/me/profileImg")
    public ResponseEntity<UserResponse> updateProfileImg(
            @AuthenticationPrincipal AuthUser authUser, @RequestPart(name = "profile") MultipartFile multipartFile
    ) throws IOException {
        String profileKey = "profiles/" + authUser.getId();
        UserResponse userResponse = userS3Service.saveProfileImage(authUser.getId(), profileKey, multipartFile);
        return ResponseEntity.ok(userResponse);
    }

    @Secured({ROLE_USER, ROLE_ADMIN})
    @DeleteMapping("/users/me/profileImg")
    public ResponseEntity<UserResponse> deleteProfileImg(@AuthenticationPrincipal AuthUser authUser) {
        userS3Service.deleteProfileImage(authUser.getId());
        return ResponseEntity.noContent().build();
    }
}
