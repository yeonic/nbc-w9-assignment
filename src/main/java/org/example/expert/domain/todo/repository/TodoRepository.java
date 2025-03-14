package org.example.expert.domain.todo.repository;

import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface TodoRepository extends JpaRepository<Todo, Long>, TodoRepositoryCustom {

    @Query("""
            SELECT t FROM Todo t
            JOIN FETCH t.user u
            WHERE (:weather IS NULL OR t.weather = :weather)
                    AND (:from IS NULL OR :from <= t.modifiedAt)
                    AND (:to IS NULL OR t.modifiedAt <= :to)
            ORDER BY t.modifiedAt DESC
            """)
    Page<Todo> findAllBySearchCond(Pageable pageable,
                                   @Param("weather") String weather,
                                   @Param("from") LocalDateTime from, @Param("to") LocalDateTime to);
}
