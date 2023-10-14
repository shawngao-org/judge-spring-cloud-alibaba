package ltd.sgtu.judge.auth.controller;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

public interface LoginController {

    @GetMapping("/oauth/login")
    String loginPage(Model model);

    @RequestMapping("/oauth/confirm_access")
    ModelAndView getAccessConfirm(Map<String, Object> model, HttpServletRequest request);
}
