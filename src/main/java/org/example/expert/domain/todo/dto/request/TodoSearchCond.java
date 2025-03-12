package org.example.expert.domain.todo.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@AllArgsConstructor
public class TodoSearchCond {

    private String weather;

    private LocalDateTime modifiedAfter;

    private LocalDateTime modifiedBefore;
}
