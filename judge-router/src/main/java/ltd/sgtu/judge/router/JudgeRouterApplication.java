package ltd.sgtu.judge.router;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.openfeign.EnableFeignClients;

@EnableFeignClients
@SpringBootApplication
@EnableDiscoveryClient
@MapperScan(basePackages = "ltd.sgtu.judge.router.mapper")
public class JudgeRouterApplication {

    public static void main(String[] args) {
        SpringApplication.run(JudgeRouterApplication.class, args);
    }

}
