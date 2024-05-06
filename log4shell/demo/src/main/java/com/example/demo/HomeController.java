package com.example.demo;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import ch.qos.logback.classic.Logger;

@RestController
public class HomeController {
    Logger log = (Logger) LoggerFactory.getLogger(HomeController.class);

    @PostMapping("/")
    public String index(@RequestBody String name) throws UnsupportedEncodingException {
        String decode = URLDecoder.decode(name, "UTF-8");
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
        log.debug("index! name:{}", decode);
        return decode;
    }
}
