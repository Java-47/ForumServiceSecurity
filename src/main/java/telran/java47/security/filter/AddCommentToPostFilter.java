package telran.java47.security.filter;

import java.io.IOException;
import java.security.Principal;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import lombok.RequiredArgsConstructor;
import telran.java47.ENUMS.Roles;
import telran.java47.accounting.dao.UserAccountRepository;
import telran.java47.accounting.model.UserAccount;
import telran.java47.post.dao.PostRepository;
import telran.java47.post.dto.exceptions.PostNotFoundException;

@Component
@RequiredArgsConstructor
@Order(60)
public class AddCommentToPostFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	final PostRepository postRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();

		if (checkEndPoint(request.getMethod(), path)) {
			Principal principal = request.getUserPrincipal();
			String[] arr = path.split("/");
			String Author = arr[arr.length - 1];
			String postId = arr[arr.length - 3];

			UserAccount userAccount = userAccountRepository.findById(principal.getName()).get();
			postRepository.findById(postId).orElseThrow(() -> new PostNotFoundException());
			if (!(principal.getName().equalsIgnoreCase(Author)
					|| userAccount.getRoles().contains(Roles.MODERATOR.name()))) {
				response.sendError(403);
				return;
			}

		}
		chain.doFilter(request, response);

	}

	private boolean checkEndPoint(String method, String path) {
		return (RequestMethod.PUT.name().equals(method) && path.matches("/forum/post/\\w+/comment/\\w+/?"));
	}

}