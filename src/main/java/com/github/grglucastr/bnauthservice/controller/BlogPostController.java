package com.github.grglucastr.bnauthservice.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/v1/posts")
public class BlogPostController {

    // Anyone authenticated can read
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAllPosts() {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        assert auth != null;

        log.info("User {} is viewing all posts", auth.getName());

        List<Map<String, ? extends Serializable>> posts = List.of(Map.of("id", 1, "title", "First Post", "author", "John"),
                Map.of("id", 2, "title", "First Post", "author", "admin"));

        Map<Object, Object> response = Map.of("posts", posts);

        return ResponseEntity.ok(response);
    }

    @PreAuthorize("hasRole('USER')")
    @PostMapping(produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> createPost(@RequestBody Map<String, String> post) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("User {} is creating a post", auth.getName());

        return ResponseEntity.ok(Map.of(
                "message", "Post created successfully",
                "post", post,
                "author", auth.getName()));
    }


    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deletePost(@PathVariable Long id) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("User {} is deleting a post {}", auth.getName(), id);

        return ResponseEntity.ok(Map.of(
                "message", "Post deleted successfully",
                "postId", id,
                "author", auth.getName()
        ));
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/dashboard")
    public ResponseEntity<?> adminDashboard() {
        return ResponseEntity.ok(Map.of(
                "message", "Welcome to admin dashboard",
                "totalUsers", 2,
                "totalPosts", 2
        ));
    }
}
