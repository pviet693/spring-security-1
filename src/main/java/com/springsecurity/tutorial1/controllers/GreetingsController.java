package com.springsecurity.tutorial1.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/greetings")
public class GreetingsController {
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from API");
    }

    @GetMapping("/say-goodbye")
    public ResponseEntity<String> sayGoodBye() {
        return ResponseEntity.ok("Good bye and see you later");
    }
}
