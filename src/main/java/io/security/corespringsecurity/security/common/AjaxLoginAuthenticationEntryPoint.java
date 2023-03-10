package io.security.corespringsecurity.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        // 인증 예외 (AuthenticationException)가 파라미터로 전달된다.
        // 인증을 받지 않은 사용자이므로 401 에러 코드를 발생시킨다.
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");

    }
}
