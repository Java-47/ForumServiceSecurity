package telran.java47.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;

@Component
@Order(30)
@RequiredArgsConstructor
public class UserFilter implements Filter {
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (request.getUserPrincipal() != null && checkEndPoint(request.getMethod(), request.getServletPath())) {
			String LoginFromRequest = request.getServletPath().replaceAll("^.*?/user/([^/]*).*", "$1");

			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).orElse(null);

			if (userAccount.getLogin().equals(LoginFromRequest)) {
				chain.doFilter(request, response);
			} else if (userAccount.getRoles().contains("ADMINISTRATOR")) {
				chain.doFilter(request, response);
				return;
			} else {
				response.sendError(403, "Access denied!");
			}

		} else {
			chain.doFilter(request, response);
		}
	}

	private boolean checkEndPoint(String method, String path) {
		return ("PUT".equalsIgnoreCase(method) && path.matches("/account/user/([^/]+)/?"))
				|| ("DELETE".equalsIgnoreCase(method) && path.matches("/account/user/([^/]+)/?"));
	}

}
