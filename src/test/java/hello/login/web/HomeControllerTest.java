package hello.login.web;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class HomeControllerTest {

    HomeController homeController;

    @Test
    void sessionLogin() {
        homeController.homeLoginV2(new MockHttpServletRequest(), new ConcurrentModel());
    }

}