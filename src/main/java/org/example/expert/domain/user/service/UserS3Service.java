package org.example.expert.domain.user.service;

import io.awspring.cloud.s3.ObjectMetadata;
import io.awspring.cloud.s3.S3Operations;
import io.awspring.cloud.s3.S3Resource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.entity.User;
import org.example.expert.domain.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

import static org.springframework.util.StringUtils.hasText;

@Slf4j @Service
@RequiredArgsConstructor
public class UserS3Service {
    private final S3Operations s3Operations;
    private final UserRepository userRepository;

    @Value("${spring.cloud.aws.s3.bucket}")
    private String bucketName;

    @Transactional
    public UserResponse saveProfileImage(Long userId, String key, MultipartFile multipartFile) throws IOException {
        if (multipartFile == null || !multipartFile.getContentType().startsWith("image")) {
            throw new InvalidRequestException("이미지 파일만 업로드가 가능합니다.");
        }

        User user = userRepository.findById(userId).orElseThrow(
                () -> new InvalidRequestException("사용자가 존재하지 않습니다.")
        );

        S3Resource uploaded = s3Operations.upload(
                bucketName, key, multipartFile.getInputStream(),
                ObjectMetadata.builder()
                        .contentType(multipartFile.getContentType())
                        .build()
        );
        user.updateProfileImgUrl(uploaded.getURL().toString());

        return UserResponse.fromUser(user);
    }

    @Transactional
    public void deleteProfileImage(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new InvalidRequestException("사용자가 존재하지 않습니다.")
        );
        if (!hasText(user.getProfileImgUrl())) {
            throw new InvalidRequestException("프로필 사진이 존재하지 않습니다.");
        }

        // url에서 object만 추출
        String profileImgUrl = user.getProfileImgUrl();
        int i = profileImgUrl.lastIndexOf("profiles");

        if (hasText(user.getProfileImgUrl())) {
            s3Operations.deleteObject(bucketName, profileImgUrl.substring(i));
        }

        user.updateProfileImgUrl("");
    }

}
