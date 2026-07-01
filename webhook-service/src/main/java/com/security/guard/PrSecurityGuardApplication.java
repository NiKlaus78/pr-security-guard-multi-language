package com.security.guard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class PrSecurityGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(PrSecurityGuardApplication.class, args);
    }
}
