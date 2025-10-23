import { UseGuards } from '@nestjs/common';
import { UserMeService } from './user-me.service';
import { User, UserRole } from 'src/userForAdmin/entities/user.entity';
import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { AuthGuard } from 'src/userForAdmin/guards/auth.guard';
import { Roles } from 'src/userForAdmin/decorators/roles.decorator';
import { UpdateUserDto } from 'src/userForAdmin/dto/updateUser.dto';
import { CurrentUser } from './currentUser.decorator';

@UseGuards(AuthGuard)
@Resolver(() => User)
export class UserMeResolver {
  constructor(private readonly usermeService: UserMeService) {}

  //Desc: User can Get his/her profile
  //Access: Private (admin, user)
  @Roles([UserRole.ADMIN, UserRole.USER])
  @Query(() => User)
  getSelf(@CurrentUser('id') userId: number): Promise<User> {
    return this.usermeService.getSelf(userId);
  }

  //Desc: User can Update his/her profile
  //Access: Private (user only)
  @Roles([UserRole.USER])
  @Mutation(() => User)
  updateSelf(@CurrentUser('id') userId: number, @Args('updateUserInput') updateUserInput: UpdateUserDto): Promise<User> {
    return this.usermeService.updateSelf(userId, updateUserInput);
  }

  //Desc: User can UnActive his/her profile
  //Route: DELETE api/v1/me
  //Access: Private (user only)
  @Roles([UserRole.USER])
  @Mutation(() => String)
  deleteSelf(@CurrentUser('id') userId: number): Promise<string> {
    return this.usermeService.deleteSelf(userId);
  }
}