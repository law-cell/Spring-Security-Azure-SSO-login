package com.example.azure.springsecurityazure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
@RequestMapping("/")
@Slf4j
public class IndexController {

    @GetMapping
    //@PreAuthorize("hasRole('ROLE_Developer')")
//    @Secured({ "ROLE_Developer", "ROLE_Developer" , "APPROLE_Developer", "APPROLE_DEVELOPER", "ROLE_USER"}) works
    @PreAuthorize("hasAnyAuthority('APPROLE_Writer', 'APPROLE_WRITER', 'ROLE_USER')")
    public String index(Model model, Authentication user) {
        log.info("GET /: user={}", user);
        model.addAttribute("user", user);
        return "index";
    }
}