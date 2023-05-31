package com.example.azure.springsecurityazure.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.HashSet;
import java.util.Set;

@Controller
@RequestMapping("/")
@Slf4j
public class IndexController {

//    @GetMapping
    //@PreAuthorize("hasRole('ROLE_Developer')")
//    @Secured({ "ROLE_Developer", "ROLE_Developer" , "APPROLE_Developer", "APPROLE_DEVELOPER", "ROLE_USER"}) works
//    @PreAuthorize("hasAnyAuthority('APPROLE_Writer', 'APPROLE_WRITER', 'ROLE_USER')")
//    @PreAuthorize("hasAuthority('ROLE_GROUP1')")
//    public String index(Model model, Authentication user) {
//        log.info("GET /: user={}", user);
//        model.addAttribute("user", user);
//        return "group1";
//    }

//    @GetMapping
//    @PreAuthorize("hasAuthority('ROLE_DEVELOPER')")
//    public String nonGroup(Model model, Authentication user) {
//        log.info("GET /: user={}", user);
//        model.addAttribute("user", user);
//        return "developerPage";
//    }

    @GetMapping
    public String login(Model model, Authentication auth) {
        model.addAttribute("user", auth);
        Set<String> userGroups = new HashSet<>();
        for (GrantedAuthority authority : auth.getAuthorities()) {
            userGroups.add(authority.getAuthority());
        }

        if (userGroups.contains("ROLE_GROUP1")) {
            return "group1";
        } else if (userGroups.contains("ROLE_DEVELOPER")) {
            return "developerPage";
        }

        return null;
    }
}
