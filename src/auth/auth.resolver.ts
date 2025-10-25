import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { ForgotPasswordDto, NewPasswordDto, LoginDto, SignUpDto, VerifyResetPasswordCodeDto } from './dto/auth.dto';
import { UsePipes, ValidationPipe } from '@nestjs/common';
import { AuthResponse, RefreshTokenResponse, MessageResponse, LogoutResponse } from './dto/auth-response';

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
  async login(@Args('loginInput') loginDto: LoginDto, @Context() context) {
    const tokens = await this.authService.login(loginDto);

    context.res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: false, // true while Production
      sameSite: 'strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Return user and access token
    return {
      message: tokens.message,
      user: tokens.user,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
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
  async refreshToken(@Context() context): Promise<RefreshTokenResponse> {
    const refreshToken = context.req.cookies?.refreshToken;
    const newTokens = await this.authService.refreshToken(refreshToken);

    // Set new refresh token in httpOnly cookie
    context.res.cookie('refreshToken', newTokens.refreshToken, {
      httpOnly: true,
      secure: false,// true while Production
      sameSite: 'strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000,// 7 days
    });

    return newTokens;
  }
  
  // Desc: User can logout
  // Mutation: logout
  // Access: Public
  @Mutation(() => LogoutResponse)
  async logout(@Context() context): Promise<LogoutResponse> {
    context.res.clearCookie('refreshToken', { path: '/' });
    return { success: true, message: 'Logged out successfully' };
  }
}