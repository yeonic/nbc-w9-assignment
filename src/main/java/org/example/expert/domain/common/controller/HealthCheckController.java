package org.example.expert.domain.common.controller;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthCheckController {

    @GetMapping("/health")
    public ResponseEntity<HealthCheckResponse> sendResponse() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noCache())
                .body(new HealthCheckResponse("ok"));
    }

    @Getter
    @AllArgsConstructor
    static class HealthCheckResponse {
        private String status;
    }
}
