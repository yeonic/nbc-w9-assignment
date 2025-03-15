package org.example.expert.domain.todo.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.todo.annotation.TodoFind;
import org.example.expert.domain.todo.dto.request.TodoSaveRequest;
import org.example.expert.domain.todo.dto.request.TodoSearchCond;
import org.example.expert.domain.todo.dto.response.TodoResponse;
import org.example.expert.domain.todo.dto.response.TodoSaveResponse;
import org.example.expert.domain.todo.service.TodoService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import static org.example.expert.domain.user.enums.UserRole.Authority.ROLE_ADMIN;
import static org.example.expert.domain.user.enums.UserRole.Authority.ROLE_USER;

@RestController
@RequiredArgsConstructor
public class TodoController {

    private final TodoService todoService;

    @Secured({ROLE_USER, ROLE_ADMIN})
    @PostMapping("/todos")
    public ResponseEntity<TodoSaveResponse> saveTodo(
            @AuthenticationPrincipal AuthUser authUser,
            @Valid @RequestBody TodoSaveRequest todoSaveRequest
    ) {
        return ResponseEntity.ok(todoService.saveTodo(authUser, todoSaveRequest));
    }

    @GetMapping("/todos")
    public ResponseEntity<Page<TodoResponse>> getTodos(
            @RequestParam(name = "page", defaultValue = "1") int page,
            @RequestParam(name = "size", defaultValue = "10") int size,
            @TodoFind TodoSearchCond cond
    ) {
        return ResponseEntity.ok(todoService.getTodos(page, size, cond));
    }

    @GetMapping("/todos/{todoId}")
    public ResponseEntity<TodoResponse> getTodo(@PathVariable long todoId) {
        return ResponseEntity.ok(todoService.getTodo(todoId));
    }
}
