package hello.login.web.ArgumentResolver;

import hello.login.domain.member.Member;
import hello.login.web.SessionConst;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Slf4j
public class LoginMemberArgumentResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        log.info("supportsParamter 실행");

        // Custom annotation이 있는지 확인
        boolean hasLoginAnnotation = parameter.hasParameterAnnotation(Login.class);
        // Customer annotaion에 해당하는 파라미터가 Member 클래스와 같나?
        boolean hasMemberType = Member.class.isAssignableFrom(parameter.getParameterType());

        // 두개가 모두 만족하면 resolveArgument 실행
        return hasMemberType && hasMemberType;
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        log.info("resolverArgument 실행");

        HttpServletRequest request = (HttpServletRequest) webRequest.getNativeRequest();
        HttpSession session = request.getSession(false);

        if(session==null) {
            return null;
        }

        return session.getAttribute(SessionConst.LOGIN_MEMEBER);

    }
}
