# 필터

웹과 관련된 공통 관심사를 처리할 때는 HTTP의 헤더나 URL의 정보들이 필요한데, 서블릿 필터나 스프링 인터셉터는 HttpServletRequest 를

## 필터

흐름
>TTP 요청 -> WAS -> 필터 -> 서블릿 -> 컨트롤러 //로그인 사용자
HTTP 요청 -> WAS -> 필터(적절하지 않은 요청이라 판단, 서블릿 호출X) //비 로그인 사용자

### 1. Filter
```
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
```

### 2. Filter Bean등록
```
@Configuration
public class WebConfig {

    @Bean
    public FilterRegistrationBean loginCheckFilter() {
        FilterRegistrationBean<Filter> filterFilterRegistrationBean = new FilterRegistrationBean<>();
        filterFilterRegistrationBean.setFilter(new LoginCheckFilter());
        filterFilterRegistrationBean.setOrder(2);
        filterFilterRegistrationBean.addUrlPatterns("/*");
        return filterFilterRegistrationBean;
    }

}
```

### 3. 로그인 Controller
```
@PostMapping("/login")
    public String loginV4(@Validated @ModelAttribute LoginForm loginForm, BindingResult bindingResult
            , @RequestParam(defaultValue = "/") String redirectURL
            , HttpServletRequest request) {

        if(bindingResult.hasErrors()) {
            return "login/loginForm";
        }

        Member loginMember = loginService.login(loginForm.getLoginId(), loginForm.getPassword());

        if(loginMember==null) {
            bindingResult.reject("loginFail", "아이디 또는 비밀번호 맞지 않습니다.");
            return "login/loginForm";
        }

        // 로그인 성공 처리 TODO
        // 세션이 있으면 있는 세션 반환, 없으면 신규 세션을 생성
        HttpSession session = request.getSession();
        // 세션에 로그인 회원 정보 보관
        session.setAttribute(SessionConst.LOGIN_MEMEBER, loginMember);

		// 로그인 페이지 이전 URL 리다이렉트
        return "redirect:"+redirectURL;
    }
```

_참고 PatternMatchUtils.simpleMatch_
```
public static boolean simpleMatch(@Nullable String[] patterns, String str) {
	if (patterns != null) {
		for (String pattern : patterns) {
			if (simpleMatch(pattern, str)) {
				return true;
			}
		}
	}
	return false;
}
```

## 인터셉터
### 1. 인터셉터의 흐름
> HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 스프링 인터셉터 -> 컨트롤러 //로그인 사용자
HTTP 요청 -> WAS -> 필터 -> 서블릿 -> 스프링 인터셉터(적절하지 않은 요청이라 판단, 컨트롤러 호출 X) // 비 로그인 사용자

![업로드중..](blob:https://velog.io/6882ca35-a0bc-4078-8c73-18431c6c9d48)

1. preHandle : 컨트롤러 호출 전에 호출된다. (더 정확히는 핸들러 어댑터 호출 전에 호출된다.)
- preHandle 의 응답값처리
    1) true : 다음으로 진행하고,
    2) false : 더는 진행하지 않는다.
2. postHandle : 컨트롤러 호출 후에 호출된다. (더 정확히는 핸들러 어댑터 호출 후에 호출된다.)
3. afterCompletion : 뷰가 렌더링 된 이후에 호출된다.

### 2. 예외상황 흐름
![업로드중..](blob:https://velog.io/9fff3265-a57b-4212-810f-741f7eac6a99)
- 예외가 발생시
1. preHandle : 컨트롤러 호출 전에 호출된다.
2. postHandle : 컨트롤러에서 예외가 발생하면 postHandle 은 호출되지 않는다.
3. afterCompletion : afterCompletion 은 항상 호출된다. 이 경우 예외( ex )를 파라미터로 받아서 어떤 예외가 발생했는지 로그로 출력할 수 있다.

- afterCompletion은 예외가 발생해도 호출된다.
1. 예외가 발생하면 postHandle() 는 호출되지 않으므로 예외와 무관하게 공통 처리를 하려면 afterCompletion() 을 사용해야 한다.
2. 예외가 발생하면 afterCompletion() 에 예외 정보( ex )를 포함해서 호출된다.

### 1. Interceptor
```
@Slf4j
public class LoginCheckInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        String requestURI = request.getRequestURI();
        HttpSession session = request.getSession();

        log.info("인증 체크 인터셉터 실행 {} ",requestURI);

        if(session==null || session.getAttribute(SessionConst.LOGIN_MEMEBER)==null) {
            log.info("미인증 사용자 요청");
            response.sendRedirect("/login?redirectURL="+requestURI);
        }

        return true;
    }
}
```

### 2. Config (인터셉터 설정)
```
@Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new LogInterceptor())
                .order(1)
                // /** : 모든 범위 적용
                .addPathPatterns("/**")
                // 이건 제외한다.
                .excludePathPatterns("/css/**", "/*.ico", "/error");
        registry.addInterceptor(new LoginCheckInterceptor())
                .order(2)
                .addPathPatterns("/**")
                // 필터에서는 체크 클래스에 설정한걸 인터셉터의 경우 세팅할때 할 수 있다. (패턴설정)
                .excludePathPatterns("/", "/members/add","logout",
                        "logout", "/css/**", "/*.icon","/error");
    }
```

## 정리
>서블릿 필터와 스프링 인터셉터는 웹과 관련된 공통 관심사를 해결하기 위한 기술이다.
서블릿 필터와 비교해서 스프링 인터셉터가 개발자 입장에서 훨씬 편리하다


### 1. 필터(Filter)의 용도 및 예시
- 공통된 보안 및 인증/인가 관련 작업
- 모든 요청에 대한 로깅 또는 감사
- 이미지/데이터 압축 및 문자열 인코딩
- Spring과 분리되어야 하는 기능

필터에서는 기본적으로 스프링과 무관하게 전역적으로 처리해야 하는 작업들을 처리할 수 있다.

대표적인 예시로 보안과 관련된 공통 작업이 있다. 필터는 인터셉터보다 앞단에서 동작하기 때문에 전역적으로 해야하는 보안 검사(XSS 방어 등)를 하여 올바른 요청이 아닐 경우 차단을 할 수 있다. 그러면 스프링 컨테이너까지 요청이 전달되지 못하고 차단되므로 안정성을 더욱 높일 수 있다.

또한 필터는 이미지나 데이터의 압축이나 문자열 인코딩과 같이 웹 애플리케이션에 전반적으로 사용되는 기능을 구현하기에 적당하다. Filter는 다음 체인으로 넘기는 ServletRequest/ServletResponse 객체를 조작할 수 있다는 점에서 Interceptor보다 훨씬 강력한 기술이다.

### 2. 인터셉터(Interceptor)의 용도 및 예시
- 세부적인 보안 및 인증/인가 공통 작업
- API 호출에 대한 로깅 또는 감사
- Controller로 넘겨주는 정보(데이터)의 가공

인터셉터에서는 클라이언트의 요청과 관련되어 전역적으로 처리해야 하는 작업들을 처리할 수 있다.

대표적으로 세부적으로 적용해야 하는 인증이나 인가와 같이 클라이언트 요청과 관련된 작업 등이 있다. 예를 들어 특정 그룹의 사용자는 어떤 기능을 사용하지 못하는 경우가 있는데, 이러한 작업들은 컨트롤러로 넘어가기 전에 검사해야 하므로 인터셉터가 처리하기에 적합하다.

또한 인터셉터는 필터와 다르게 HttpServletRequest나 HttpServletResponse 등과 같은 객체를 제공받으므로 객체 자체를 조작할 수는 없다. 대신 해당 객체가 내부적으로 갖는 값은 조작할 수 있으므로 컨트롤러로 넘겨주기 위한 정보를 가공하기에 용이하다. 예를 들어 JWT 토큰 정보를 파싱해서 컨트롤러에게 사용자의 정보를 제공하도록 가공할 수 있는 것이다.

그 외에도 우리는 다양한 목적으로 API 호출에 대한 정보들을 기록해야 할 수 있다. 이러한 경우에 HttpServletRequest나 HttpServletResponse를 제공해주는 인터셉터는 클라이언트의 IP나 요청 정보들을 포함해 기록하기에 용이하다.

정리 출처: https://mangkyu.tistory.com/173 [MangKyu's Diary]

# ArgumentResolvers

아래의 예는 간단한 로그인 후 홈화면으로 넘어갈때 회원정보 객체 Model을 Session에 담아 로그인 후처리 하는 부분을 ArgumentResolver @Login을 등록하여 객체를 반환하는 예제이다.

## AS-IS
public String home(_**@SessionAttribute(name=SessionConst.LOGIN_MEMEBER, required = false)**_ Member member)

## TO-BE
public String homeArgumentResolver(_**@Login**_ Member member)

### 1. Annotaion 등록
```
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface Login {

}
```

### 2. HandlerMethodArgumentResolver 등록
1. supportsParameter : 해당 호출이 지원하는 상태인지 확인
2. 지원한다면 Custom Logic 및 해당 객체 리턴
```
public class LoginMemberArgumentResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        log.info("supportsParamter 실행");

        // Custom annotation이 있는지 확인 (내가 등록한 Customer anntation : Login.class)
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
```

### 3. Config 등록
resolvers.add(내가 등록한 ArgumentResolver 클래스);
```
	@Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new LoginMemberArgumentResolver());
    }
```