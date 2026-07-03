package demo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// A real Spring MVC controller. @RequestParam binds untrusted query input to a
// bare String parameter, which is concatenated into a JdbcTemplate query — the
// classic Spring SQL-injection shape. The Godzilla Java frontend builds this
// module with Gradle (so Spring is on the classpath), then analyzes the compiled
// bytecode: @RequestParam is synthesized as a taint source and JdbcTemplate.query
// is the sink.
@RestController
public class UserController {

    private final JdbcTemplate jdbc;

    public UserController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/user")
    public String getUser(@RequestParam String id) {
        return jdbc.queryForObject(
                "SELECT name FROM users WHERE id = '" + id + "'", String.class);
    }
}
