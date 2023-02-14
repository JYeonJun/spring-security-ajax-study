package io.security.corespringsecurity.security.common;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        // 파라미터로 인가 예외 (AccessDeniedException)가 전달된다.
        // 해당 자원에 권한이 없으므로 403 에러를 발생한다.
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access is denied");
    }
}
