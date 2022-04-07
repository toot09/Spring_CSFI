package hello.login.web.filter;

import hello.login.web.SessionConst;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.PatternMatchUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.regex.Pattern;

@Slf4j
public class LoginCheckFilter implements Filter {

    // 로그인이 필요없는 URI
    private static final String[] whitelist = {"/", "/members/add", "/login", "/logout", "/css/*"};

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String requestURI = httpServletRequest.getRequestURI();

        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        try {

            if(isLoginCheckPath(requestURI)) {
                log.info("인증 체크 로직 실행 {}",requestURI);
                // false일 경우에는 세션이 없다면 만들어주지 않는다.
                HttpSession session = httpServletRequest.getSession(false);
                if(session==null || session.getAttribute(SessionConst.LOGIN_MEMEBER)==null) {
                    log.info("미인증 사용자 요청 {}",requestURI);
                    //로그인으로 redirect
                    //로그인 페이지로 넘기고 로그인 후에는 지금 페이지를 다시 리다이렉트 하기위해 requestURI를 넣어준다.
                    httpServletResponse.sendRedirect("/login?redirectURL="+requestURI);
                    return ;
                }
            }

            chain.doFilter(request, response);

        } catch (Exception e) {
            throw e;
        } finally {
            log.info("인증필터 체크 종료 {}",requestURI);
        }

    }

    /**
     * 화이트 리스트의 경우 인증체크X
     */
    private boolean isLoginCheckPath(String requestURI) {
        return !PatternMatchUtils.simpleMatch(whitelist, requestURI);
    }
}
