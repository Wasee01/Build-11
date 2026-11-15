package edu.example.crs.enrollment;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;

import edu.example.crs.catalog.CourseService;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class EnrollmentService {

    private static final String CAN_MANAGE = """
            hasRole('REGISTRAR')
            or (hasRole('STUDENT') and authentication.name == #student)
            or (hasRole('ADVISOR') and @caseload.contains(authentication.name, #student))
            """;

    private final CourseService courses;
    private final Map<String, ConcurrentNavigableMap<String, Enrollment>> enrollments = Map.of(
            "alice", new ConcurrentSkipListMap<>(),
            "bob", new ConcurrentSkipListMap<>());

    public EnrollmentService(CourseService courses) {
        this.courses = courses;
        enrollments.get("alice").put("CS101", new Enrollment("alice", "CS101"));
        enrollments.get("bob").put("CS201", new Enrollment("bob", "CS201"));
    }

    @PreAuthorize(CAN_MANAGE)
    public List<Enrollment> list(String student) {
        return List.copyOf(forStudent(student).values());
    }

    @PreAuthorize(CAN_MANAGE)
    public Enrollment add(String student, String courseCode) {
        var studentEnrollments = forStudent(student);
        if (courseCode == null || courseCode.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide a course code.");
        }

        courses.get(courseCode);
        var enrollment = new Enrollment(student, courseCode);
        if (studentEnrollments.putIfAbsent(courseCode, enrollment) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Student is already enrolled in this course.");
        }

        return enrollment;
    }

    @PreAuthorize(CAN_MANAGE)
    public void drop(String student, String courseCode) {
        if (forStudent(student).remove(courseCode) == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Enrollment was not found.");
        }
    }

    private ConcurrentNavigableMap<String, Enrollment> forStudent(String student) {
        var studentEnrollments = enrollments.get(student);
        if (studentEnrollments == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Student was not found.");
        }

        return studentEnrollments;
    }

    public record Enrollment(String student, String courseCode) {
    }
}
