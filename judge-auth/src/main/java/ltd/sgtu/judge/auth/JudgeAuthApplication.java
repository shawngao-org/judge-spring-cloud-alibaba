package ltd.sgtu.judge.auth;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
@MapperScan(basePackages = "ltd.sgtu.judge.auth.mapper")
public class JudgeAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(JudgeAuthApplication.class, args);
    }
}
