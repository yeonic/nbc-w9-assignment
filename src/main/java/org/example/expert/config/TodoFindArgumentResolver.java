package org.example.expert.config;

import org.example.expert.domain.todo.annotation.TodoFind;
import org.example.expert.domain.todo.dto.request.TodoSearchCond;
import org.springframework.core.MethodParameter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class TodoFindArgumentResolver implements HandlerMethodArgumentResolver {
    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    @Override public boolean supportsParameter(MethodParameter parameter) {
        boolean hasAnnotation = parameter.hasParameterAnnotation(TodoFind.class);
        boolean isAssignable = TodoSearchCond.class.equals(parameter.getParameterType());
        return hasAnnotation && isAssignable;
    }

    @Override public Object resolveArgument(
            MethodParameter parameter, ModelAndViewContainer mavContainer,
            NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception
    {
        String weather = webRequest.getParameter("weather");

        String after = webRequest.getParameter("modifiedAfter");
        String before = webRequest.getParameter("modifiedBefore");


        LocalDateTime modifiedAfter = StringUtils.hasText(after) ? LocalDate.parse(after, FORMATTER).atStartOfDay() : null;
        LocalDateTime modifiedBefore = StringUtils.hasText(before) ? LocalDate.parse(before, FORMATTER).atTime(23, 59, 59) : null;

        return new TodoSearchCond(weather, modifiedAfter, modifiedBefore);
    }
}
