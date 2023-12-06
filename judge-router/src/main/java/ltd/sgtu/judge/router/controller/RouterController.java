package ltd.sgtu.judge.router.controller;

import ltd.sgtu.judge.router.entity.Router;
import ltd.sgtu.judge.router.service.RouterService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/router")
public class RouterController {

    private final RouterService routerService;

    public RouterController(RouterService routerService) {
        this.routerService = routerService;
    }

    @GetMapping("findAll")
    public List<Router> findAll() {
        return routerService.findAll();
    }
}
