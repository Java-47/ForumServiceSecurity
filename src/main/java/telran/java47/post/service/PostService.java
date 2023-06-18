package telran.java47.post.service;

import java.util.List;

import telran.java47.post.dto.DatePeriodDto;
import telran.java47.post.dto.NewCommentDto;
import telran.java47.post.dto.NewPostDto;
import telran.java47.post.dto.PostDto;

public interface PostService {
	PostDto addNewPost(String author, NewPostDto newPostDto);

	PostDto findPostById(String id);

	PostDto removePost(String id);

	PostDto updatePost(String id, NewPostDto newPostDto);

	PostDto addComment(String id, String author, NewCommentDto newCommentDto);

	void addLike(String id);

	Iterable<PostDto> findPostByAuthor(String author);

	Iterable<PostDto> findPostsByTags(List<String> tags);

	Iterable<PostDto> findPostsByPeriod(DatePeriodDto datePeriodDto);

}
