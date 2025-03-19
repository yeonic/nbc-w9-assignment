package org.example.expert.domain.user.repostory;

import lombok.RequiredArgsConstructor;
import org.example.expert.domain.user.entity.User;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class BulkRepository {
    private final JdbcTemplate jdbcTemplate;

    public void saveAll(List<User> entities) {
        jdbcTemplate.batchUpdate(
                "insert into users(id, email, password, nickname, user_role, profile_img_url)" +
                        " values (?, ?, ?, ?, ?, ?)",
                new BatchPreparedStatementSetter() {
                    @Override
                    public void setValues(PreparedStatement ps, int i) throws SQLException {
                        User current = entities.get(i);
                        ps.setLong(1, current.getId());
                        ps.setString(2, current.getEmail());
                        ps.setString(3, current.getPassword());
                        ps.setString(4, current.getNickname());
                        ps.setString(5, current.getUserRole().name());
                        ps.setString(6, "");
                    }

                    @Override
                    public int getBatchSize() {
                        return entities.size();
                    }
                });
    }
}
