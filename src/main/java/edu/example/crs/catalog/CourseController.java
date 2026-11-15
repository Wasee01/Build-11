package edu.example.crs.catalog;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/courses")
class CourseController {

    private final CourseService courses;

    CourseController(CourseService courses) {
        this.courses = courses;
    }

    @GetMapping
    List<Course> list() {
        return courses.list();
    }

    @GetMapping("/{code}")
    Course get(@PathVariable String code) {
        return courses.get(code);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    Course create(@RequestBody Course course) {
        return courses.create(course);
    }
}
