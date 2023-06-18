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
@Order(20)
@RequiredArgsConstructor
public class AdminFilter implements Filter {
	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (request.getUserPrincipal() != null && checkAdminEndpoints(request.getMethod(), request.getServletPath())
				&& checkEndPointPassword(request.getMethod(), request.getServletPath())
				&& checkEndPointAccountUser(request.getMethod(), request.getServletPath())

		) {
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).orElse(null);

			// pass "/user/{login}"
			if (!userAccount.getRoles().contains("ADMINISTRATOR") && checkDeleteToPass(request.getMethod(), request.getServletPath())) {
				chain.doFilter(request, response);
				return;
			} else if (userAccount.getRoles().contains("ADMINISTRATOR")) {
				chain.doFilter(request, response);
				return;
			} 
			response.sendError(403, "Access denied!");
			return;
		}

		chain.doFilter(request, response);
	}

	private boolean checkDeleteToPass(String method, String path) {
		return ("DELETE".equalsIgnoreCase(method)) && path.matches("/account/user/[^/]+/?");
	}

	private boolean checkAdminEndpoints(String method, String path) {
		boolean putOrDeleteRole = ("PUT".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method))
				&& path.matches("/account/user/[^/]+/role/[^/]+/?");
		boolean deleteUser = "DELETE".equalsIgnoreCase(method) && path.matches("/account/user/[^/]+/?");

		return putOrDeleteRole || deleteUser;
	}

	private boolean checkEndPointPassword(String method, String path) {
		return !("PUT".equalsIgnoreCase(method) && path.matches("/account/password/?"));
	}

	private boolean checkEndPointAccountUser(String method, String path) {
		return !("GET".equalsIgnoreCase(method) && path.matches("/account/user/([^/]+)/?"));
	}

}
