import { ObjectType, Field } from '@nestjs/graphql';
import { User } from 'src/userForAdmin/entities/user.entity';

@ObjectType()
export class AuthResponse {
  @Field({nullable: true})
  message?: string;

  @Field(() => User)
  user: User;

  @Field()
  accessToken?: string;

  @Field({ nullable: true })
  refreshToken?: string;
}

@ObjectType() 
export class RefreshTokenResponse {
  @Field()
  accessToken: string;

  @Field()
  refreshToken: string;
}

@ObjectType()
export class LogoutResponse {
  @Field()
  success: boolean;

  @Field({ nullable: true })
  message?: string;
}

@ObjectType()
export class MessageResponse {
  @Field()
  message: string;

  @Field({ nullable: true })
  code?: string;
}