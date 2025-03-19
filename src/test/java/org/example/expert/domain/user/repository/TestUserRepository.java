package org.example.expert.domain.user.repository;

import org.example.expert.domain.user.dto.UserWithIdAndNickname;
import org.example.expert.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface TestUserRepository extends JpaRepository<User, Long> {

    @Query("select new org.example.expert.domain.user.dto.UserWithIdAndNickname(u.id, u.nickname) from User u where u.nickname = :nickname")
    Optional<UserWithIdAndNickname> findUserByNickname(@Param("nickname") String nickName);
}
