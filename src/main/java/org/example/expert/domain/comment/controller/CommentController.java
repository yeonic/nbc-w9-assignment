package org.example.expert.domain.comment.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.comment.dto.request.CommentSaveRequest;
import org.example.expert.domain.comment.dto.response.CommentResponse;
import org.example.expert.domain.comment.dto.response.CommentSaveResponse;
import org.example.expert.domain.comment.service.CommentService;
import org.example.expert.domain.common.dto.AuthUser;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.example.expert.domain.user.enums.UserRole.Authority.ROLE_ADMIN;
import static org.example.expert.domain.user.enums.UserRole.Authority.ROLE_USER;

@RestController
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;

    @Secured({ROLE_USER, ROLE_ADMIN})
    @PostMapping("/todos/{todoId}/comments")
    public ResponseEntity<CommentSaveResponse> saveComment(
            @AuthenticationPrincipal AuthUser authUser,
            @PathVariable long todoId,
            @Valid @RequestBody CommentSaveRequest commentSaveRequest
    ) {
        return ResponseEntity.ok(commentService.saveComment(authUser, todoId, commentSaveRequest));
    }

    @GetMapping("/todos/{todoId}/comments")
    public ResponseEntity<List<CommentResponse>> getComments(@PathVariable long todoId) {
        return ResponseEntity.ok(commentService.getComments(todoId));
    }
}
