package org.example.expert.domain.todo.repository;

import com.querydsl.core.types.Projections;
import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.JPAExpressions;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.manager.entity.QManager;
import org.example.expert.domain.todo.dto.request.TodoSearchCond;
import org.example.expert.domain.todo.dto.response.TodoSearchResponse;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.user.entity.QUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import static org.example.expert.domain.manager.entity.QManager.manager;
import static org.example.expert.domain.todo.entity.QTodo.todo;
import static org.example.expert.domain.user.entity.QUser.user;
import static org.springframework.util.StringUtils.hasText;

@RequiredArgsConstructor
public class TodoRepositoryImpl implements TodoRepositoryCustom {
    private final JPAQueryFactory queryFactory;

    @Override
    public Optional<Todo> findByIdWithUser(Long todoId) {
        return Optional.ofNullable(
                queryFactory
                        .select(todo)
                        .from(todo)
                        .join(todo.user, user).fetchJoin()
                        .where(todo.id.eq(todoId))
                        .fetchOne());
    }

    @Override
    public Page<TodoSearchResponse> findAllBySearchCond(Pageable pageable, TodoSearchCond cond) {
        List<TodoSearchResponse> content = queryFactory
                .select(Projections.constructor(
                                TodoSearchResponse.class, todo.title,
                                todo.managers.size(),
                                todo.comments.size()
                        )
                )
                .from(todo)
                .join(todo.managers, manager)
                .where(titleLike(cond.getTitle()), createdAfter(cond.getCreatedAfter()),
                        createdBefore(cond.getCreatedBefore()), managerNicknameLike(cond.getManagerNickname())
                )
                .orderBy(todo.createdAt.desc())
                .groupBy(todo.id)
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        JPAQuery<Long> countQuery = queryFactory
                .select(todo.count())
                .from(todo)
                .where(titleLike(cond.getTitle()), createdAfter(cond.getCreatedAfter()),
                        createdBefore(cond.getCreatedBefore()), managerNicknameLike(cond.getManagerNickname())
                );

        return PageableExecutionUtils.getPage(content, pageable, countQuery::fetchOne);
    }

    private BooleanExpression titleLike(String title) {
        return title != null ? todo.title.like("%" + title + "%") : null;
    }

    private BooleanExpression createdAfter(LocalDate createdAfter) {
        return createdAfter != null ? todo.createdAt.after(createdAfter.atStartOfDay()) : null;
    }

    private BooleanExpression createdBefore(LocalDate createdBefore) {
        return createdBefore != null ? todo.createdAt.before(createdBefore.atTime(23, 59, 59)) : null;
    }

    private BooleanExpression managerNicknameLike(String managerNickname) {
        if (!hasText(managerNickname)) {
            return null;
        }

        QManager subManager = new QManager("subManager");
        QUser subUser = new QUser("subUser");

        return JPAExpressions
                .selectOne()
                .from(subManager)
                .join(subManager.user, subUser)
                .where(subManager.user.nickname.like("%" + managerNickname + "%"),
                        subManager.in(todo.managers))
                .exists();
    }
    
}
