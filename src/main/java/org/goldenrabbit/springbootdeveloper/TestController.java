package org.goldenrabbit.springbootdeveloper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class TestController {
    @Autowired
    private TestService testService;

    @GetMapping("/test")
    public List<Member> getAllMemebers() {
        List<Member> members = testService.getAllMembers();
        return members;
    }


}
