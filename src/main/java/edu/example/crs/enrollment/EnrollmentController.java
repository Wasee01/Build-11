package edu.example.crs.enrollment;

import java.util.List;

import edu.example.crs.enrollment.EnrollmentService.Enrollment;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/students/{student}/enrollments")
class EnrollmentController {

    private final EnrollmentService enrollments;

    EnrollmentController(EnrollmentService enrollments) {
        this.enrollments = enrollments;
    }

    @GetMapping
    List<Enrollment> list(@PathVariable String student) {
        return enrollments.list(student);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    Enrollment add(@PathVariable String student, @RequestBody EnrollmentRequest request) {
        return enrollments.add(student, request.courseCode());
    }

    @DeleteMapping("/{courseCode}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void drop(@PathVariable String student, @PathVariable String courseCode) {
        enrollments.drop(student, courseCode);
    }

    record EnrollmentRequest(String courseCode) {
    }
}
