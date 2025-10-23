import { Args, Mutation, Query, Resolver } from "@nestjs/graphql";
import { User, UserRole } from "./entities/user.entity";
import { CreateUserDto } from "./dto/createUser.dto";
import { UpdateUserDto } from "./dto/updateUser.dto";
import { UserService } from "./user.service";
import { UseGuards } from "@nestjs/common";
import { AuthGuard } from "./guards/auth.guard";
import { Roles } from "./decorators/roles.decorator";

@UseGuards(AuthGuard)
@Resolver(() => User)
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  //Desc: Admin can Create a new user
  //Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Mutation(() => User)
  async addUser(@Args('createUserInput') createUserDto: CreateUserDto): Promise<User> {
    return this.userService.addUser(createUserDto);
  }
  
  //Desc: Admin can Get all users
  //Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Query(() => [User])
  allUsers(): Promise<User[]> {
    return this.userService.allUsers();
  }
  
  //Desc: Admin can Get a single user
  //Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Query(() => User)
  getUserById(@Args('id') id: number): Promise<User> {
    return this.userService.getUserById(id);
  }
  
  //Desc: Admin can Update a user
  //Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Mutation(() => User)
  updateUserAsAdmin(@Args('id') id: number, @Args('updateUserInput') updateUserInput: UpdateUserDto): Promise<User> {
    return this.userService.updateUserAsAdmin(id, updateUserInput);
  }
  
  //Desc: Admin can Delete a user
  //Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Mutation(() => String)
  deleteUserAsAdmin(@Args('id') id: number): Promise<string> {
    return this.userService.deleteUserAsAdmin(id);
  }
}