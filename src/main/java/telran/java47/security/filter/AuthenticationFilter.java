package telran.java47.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;

@Component
@RequiredArgsConstructor
@Order(10)
public class AuthenticationFilter implements Filter {

	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String[] credentials;
			try {
				credentials = getCredentials(request.getHeader("Authorization"));
			} catch (Exception e) {
				response.sendError(401, "token not valid");
				return;
			}
			UserAccount userAccount = userAccountRepository.findById(credentials[0]).orElse(null);
			if (userAccount == null || !BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
				response.sendError(401, "login or password is not valid");
				return;
			}
			request = new WrappedRequest(request, credentials[0]);
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		return !("POST".equalsIgnoreCase(method) && path.matches("/account/register/?"));
	}

	private String[] getCredentials(String token) {
		token = token.substring(6);
		String decode = new String(Base64.getDecoder().decode(token));
		return decode.split(":");
	}

	private static class WrappedRequest extends HttpServletRequestWrapper {
		String login;

		public WrappedRequest(HttpServletRequest request, String login) {
			super(request);
			this.login = login;
		}

		@Override
		public Principal getUserPrincipal() {
			return () -> login;
		}

	}

}
