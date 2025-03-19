package org.example.expert;

import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.dto.UserWithIdAndNickname;
import org.example.expert.domain.user.repository.BulkRepository;
import org.example.expert.domain.user.repository.TestUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Commit;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@SpringBootTest
@Transactional
@Commit @Slf4j
public class MassiveDataTest {

    public static final int BATCH_SIZE = 1000;
    @Autowired BulkRepository bulkRepository;
    @Autowired TestUserRepository userRepository;

    /*@BeforeEach
    void before() {

        List<User> insertList = new ArrayList<>();
        for (int i = 0; i < 1_000_000; i++) {
            User user = new User(
                    String.format("example%s@example.com", i), "Abcd1234!",
                    UserRole.ROLE_USER, "user" + i);
            ReflectionTestUtils.setField(user, "id", (long) (i + 1));

            insertList.add(user);
        }

        for (int i = 0; i < 990_000; i += BATCH_SIZE) {
            bulkRepository.saveAll(insertList.subList(i, i + BATCH_SIZE));
        }
    }*/

    @Test
    void 닉네임으로_유저를_조회하는_성능을_측정한다() {
        long totalElapsed = 0;

        // 100번 실행한 값의 평균을 낸다.
        for (int i = 0; i < 100; i++) {
            long start = System.currentTimeMillis();
            Optional<UserWithIdAndNickname> user500000 = userRepository.findUserByNickname("user500000");
            long end = System.currentTimeMillis();
            totalElapsed += end - start;
        }
        double avgElapsed = totalElapsed / 100.0;

        log.info("avg elapsed time : {} ms", avgElapsed);
    }
}
