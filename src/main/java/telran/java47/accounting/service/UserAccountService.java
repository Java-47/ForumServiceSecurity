package telran.java47.accounting.service;

import telran.java47.accounting.dto.RolesDto;
import telran.java47.accounting.dto.UserDto;
import telran.java47.accounting.dto.UserEditDto;
import telran.java47.accounting.dto.UserRegisterDto;

public interface UserAccountService {

	UserDto register(UserRegisterDto userRegisterDto);

	UserDto getUser(String login);

	UserDto removeUser(String login);

	UserDto updateUser(String login, UserEditDto userEditDto);

	RolesDto changeRolesList(String login, String role, boolean isAddRole);

	void changePassword(String login, String newPassword);

}
