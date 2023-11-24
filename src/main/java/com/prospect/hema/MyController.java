package com.prospect.hema;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping
public class MyController {


    @RolesAllowed("Labo")
    @GetMapping("/allylabo")
    public ResponseEntity<String> getMyLabo(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok("Hello labo");
    }

    @RolesAllowed("Reception")
    @GetMapping("/allyReception")
    public ResponseEntity<String> getReception() {
        return ResponseEntity.ok("Hello Reception");
    }

    @RolesAllowed("ROLE_Reception")
    @RequestMapping(value = "/Reception", method = RequestMethod.GET)
    public ResponseEntity<String> getReception(@RequestHeader String Authorization) {
        return ResponseEntity.ok("Hello Reception");
    }

    @RolesAllowed("Labo")
    @RequestMapping(value = "/Labo", method = RequestMethod.GET)
    public ResponseEntity<String> getLabo(@RequestHeader String Authorization) {
        System.out.print(Authorization);
        return ResponseEntity.ok("Hello Labo");
    }

    @RolesAllowed({ "ROLE_Labo", "ROLE_Reception" })
    @RequestMapping(value = "/LaboReception", method = RequestMethod.GET)
    public ResponseEntity<String> getAllUser(@RequestHeader String Authorization) {
        return ResponseEntity.ok("Hello All User Labo_Reception");
    }
}