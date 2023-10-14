package ltd.sgtu.judge.auth.controller.impl;

import ltd.sgtu.judge.auth.controller.LoginController;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

@RestController
@RequestMapping
@SessionAttributes("authorizationRequest")
public class ILoginController implements LoginController {

    @Override
    public String loginPage(Model model) {
        try {
            InputStream inputStream = this.getClass().getResourceAsStream("/login.html");
            if (inputStream != null) {
                return new String(inputStream.readAllBytes());
            } else {
                return "404 - FileNotFound";
            }
        } catch (IOException e) {
            e.printStackTrace();
            return e.getMessage();
        }
    }

    @Override
    public ModelAndView getAccessConfirm(Map<String, Object> model, HttpServletRequest request) {
        AuthorizationRequest authorizationRequest = (AuthorizationRequest) model.get("authorizationRequest");
        ModelAndView view = new ModelAndView();
        view.setViewName("grant");
        view.addObject("clientId", authorizationRequest.getClientId());
        view.addObject("scopes",authorizationRequest.getScope());
        return view;
    }
}
