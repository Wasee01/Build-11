package edu.example.crs.enrollment;

import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

@Component
public class Caseload {

    private final Map<String, Set<String>> assignments = Map.of("advisor", Set.of("alice"));

    public boolean contains(String advisor, String student) {
        return assignments.getOrDefault(advisor, Set.of()).contains(student);
    }
}
