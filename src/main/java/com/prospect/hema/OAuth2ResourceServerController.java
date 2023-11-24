package com.prospect.hema;
/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import jakarta.annotation.security.RolesAllowed;
import org.apache.commons.logging.Log;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
public class OAuth2ResourceServerController {

    @GetMapping("/papa")
    public String index(@AuthenticationPrincipal Jwt jwt) {
        return String.format("Hello, %s!", jwt.getClaimAsString("preferred_username"));
    }


    @GetMapping("/ddd")
    @PreAuthorize("hasRole('ROLE_user')")
    public String premium(@AuthenticationPrincipal Jwt jwt) {

        return String.format("Hello dd, %s!", jwt.getClaimAsString("preferred_username"));
    }
    @GetMapping("/bb")
    //@Secured({ "user"})
    //@PreAuthorize("hasRole('user')")
    public String premiumbb(@AuthenticationPrincipal Jwt jwt) {

        return String.format("Hello dd, %s!", jwt.getClaimAsString("preferred_username"));
    }


    @RolesAllowed("Labo")
    @GetMapping("/mum")
    public String premim(@AuthenticationPrincipal Jwt jwt) {
        return String.format("Hello mum, %s!", jwt.getClaimAsString("preferred_username"));
    }
}