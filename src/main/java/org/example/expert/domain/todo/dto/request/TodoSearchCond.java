package org.example.expert.domain.todo.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

@Getter
@AllArgsConstructor
public class TodoSearchCond {

    private String title; // 부분 일치 가능

    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private LocalDate createdAfter;

    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private LocalDate createdBefore;

    private String managerNickname;
}
