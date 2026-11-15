package edu.example.crs;

import java.io.Console;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SecuredCrsApplication {

    public static void main(String[] args) {
        if (args.length == 1 && "--hash-password".equals(args[0])) {
            printPasswordHash();
            return;
        }

        SpringApplication.run(SecuredCrsApplication.class, args);
    }

    private static void printPasswordHash() {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Run the hash command in an interactive terminal.");
        }

        char[] password = console.readPassword("Password: ");
        if (password == null) {
            throw new IllegalArgumentException("A password is required.");
        }

        try {
            int bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password)).remaining();
            if (password.length < 12 || bytes > 72) {
                throw new IllegalArgumentException("Use at least 12 characters and at most 72 UTF-8 bytes.");
            }
            console.printf("%s%n", new BCryptPasswordEncoder().encode(CharBuffer.wrap(password)));
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
