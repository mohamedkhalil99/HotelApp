import { Field, InputType } from "@nestjs/graphql";
import { IsEmail, IsEnum, IsNotEmpty, IsOptional, IsString, Length, MaxLength, MinLength } from "class-validator";
import { UserRole } from "../entities/user.entity";

@InputType()
export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  @Field()
  username: string;

  @IsNotEmpty()
  @IsEmail()
  @Field()
  email: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @MaxLength(20)
  @Field()
  password: string;
  
  @IsEnum(UserRole)
  @IsOptional()
  @Field(() => UserRole, { nullable: true })
  role?: UserRole;
  
  @IsOptional()    
  @IsString()
  @Length(6, 6, { message: 'Verification code must be at least 6 characters long' })
  @Field({ nullable: true })
  verificationCode: string;
}