package com.example.api;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    // Authorized endpoint
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public User getUser(@PathVariable Long id) {
        return userService.find(id);
    }

    // Public create (no auth annotation)
    @PostMapping
    public User createUser(@RequestBody User u) {
        return userService.save(u);
    }

    // Generic RequestMapping with explicit method, no auth
    @RequestMapping(value = "/search", method = RequestMethod.GET)
    public java.util.List<User> search() {
        return userService.all();
    }
}
