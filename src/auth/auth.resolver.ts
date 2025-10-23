import { Resolver, Mutation, Args } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { ForgotPasswordDto, NewPasswordDto, RefreshTokenDto, LoginDto, SignUpDto, VerifyResetPasswordCodeDto } from './dto/auth.dto';
import { UsePipes, ValidationPipe } from '@nestjs/common';
import { AuthResponse, RefreshTokenResponse, MessageResponse } from './dto/auth-response';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  // Desc: Anyone can sign up
  // Mutation: signUp
  // Access: Public
  @Mutation(() => AuthResponse)
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  signUp(@Args('signUpInput') signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  // Desc: User can sign in
  // Mutation: signIn
  // Access: Public
  @Mutation(() => AuthResponse)
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  login(@Args('loginInput') loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  // Desc: User can reset password
  // Mutation: forgotPassword
  // Access: Public
  @Mutation(() => MessageResponse)
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async forgotPassword(@Args('forgotPasswordInput') emailDto: ForgotPasswordDto): Promise<MessageResponse> {
    return this.authService.forgotPassword(emailDto);
  }

  // Desc: User can verify the reset password code
  // Mutation: verifyResetPasswordCode
  // Access: Public
  @Mutation(() => MessageResponse)
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async verifyResetPasswordCode(@Args('verifyResetCodeInput') verifyDto: VerifyResetPasswordCodeDto): Promise<MessageResponse> {
    return this.authService.verifyResetPasswordCode(verifyDto);
  }

  // Desc: User can set a new password
  // Mutation: resetPassword
  // Access: Public
  @Mutation(() => MessageResponse)
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async resetPassword(@Args('resetPasswordInput') newPassDto: NewPasswordDto): Promise<MessageResponse> {
    return this.authService.newPassword(newPassDto);
  }

  // Desc: User can refresh access token
  // Mutation: refreshToken
  // Access: Public
  @Mutation(() => RefreshTokenResponse)
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  refreshToken(@Args('refreshTokenInput') refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto);
  }
}