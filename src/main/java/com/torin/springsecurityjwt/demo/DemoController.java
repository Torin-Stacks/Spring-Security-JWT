package com.torin.springsecurityjwt.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
@RequiredArgsConstructor
public class DemoController {

    @GetMapping("")
    public ResponseEntity<?> seyHi(){
        return new ResponseEntity<>("hello from a secured endpoint", HttpStatus.OK);
    }
}
