package edu.example.crs.catalog;

import java.util.List;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CourseService {

    private final ConcurrentNavigableMap<String, Course> courses = new ConcurrentSkipListMap<>();

    public CourseService() {
        courses.put("CS101", new Course("CS101", "Introduction to Programming"));
        courses.put("CS201", new Course("CS201", "Data Structures"));
    }

    @PreAuthorize("isAuthenticated()")
    public List<Course> list() {
        return List.copyOf(courses.values());
    }

    @PreAuthorize("isAuthenticated()")
    public Course get(String code) {
        Course course = courses.get(code);
        if (course == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Course was not found.");
        }

        return course;
    }

    @PreAuthorize("hasRole('REGISTRAR')")
    public Course create(Course course) {
        if (course.code() == null || !course.code().matches("[A-Z][A-Z0-9]{1,15}")
                || course.title() == null || course.title().isBlank() || course.title().length() > 120) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide a valid course code and title.");
        }

        if (courses.putIfAbsent(course.code(), course) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Course code already exists.");
        }

        return course;
    }
}
