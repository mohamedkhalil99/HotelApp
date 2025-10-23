import { ConflictException, Injectable, UnauthorizedException, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { ForgotPasswordDto, NewPasswordDto, RefreshTokenDto, LoginDto, SignUpDto, VerifyResetPasswordCodeDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import * as nodemailer from 'nodemailer';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { instanceToPlain } from 'class-transformer'; // 💡 تم التأكيد على استخدامها
import { User, UserRole } from 'src/userForAdmin/entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { AuthResponse, RefreshTokenResponse, MessageResponse } from './dto/auth-response';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>, 
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // 🟢 SIGN UP
  async signUp(signUpInput: SignUpDto): Promise<AuthResponse> {
    try {
      const { username, email, password } = signUpInput;

      const existingUser = await this.userRepo.findOne({ where: { email } });
      if (existingUser) {
        throw new ConflictException('User already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const user = this.userRepo.create({
        username,
        email,
        password: hashedPassword,
        role: UserRole.USER,
      });

      const savedUser = await this.userRepo.save(user);

      // 💡 التعديل 1: تطبيق instanceToPlain لإزالة الحقول الحساسة (@Exclude) قبل الإرجاع
      const safeUser = instanceToPlain(savedUser) as User; 

      const payload = { 
        email: savedUser.email, 
        role: savedUser.role, 
        id: savedUser.id,
        username: savedUser.username 
      };
      
      const accessToken = await this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_KEY'),
        expiresIn: '15m',
      });

      const refreshToken = await this.jwtService.signAsync(
        { ...payload, countEX: 5 },
        {
          secret: this.configService.get<string>('JWT_REFRESH_KEY'),
          expiresIn: '7d',
        },
      );

      return { user: safeUser, accessToken, refreshToken, message: 'User created successfully'};
    } 
    catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      throw new InternalServerErrorException('Error during sign up');
    }
  }

  // 🟡 LOGIN
  async login(loginDto: LoginDto): Promise<AuthResponse> {
    try {
      // 💡 (تحسين): إضافة select للحقول الحساسة لضمان استرجاعها للمقارنة
      const user = await this.userRepo.findOne({
        where: { email: loginDto.email },
        select: ['id', 'email', 'password', 'role', 'username', 'verificationCode', 'verificationCodeExpires'],
      });

      if (!user) {
        throw new UnauthorizedException('Invalid email or password');
      }

      const isMatch = await bcrypt.compare(loginDto.password, user.password);
      if (!isMatch) {
        throw new UnauthorizedException('Invalid email or password');
      }

      const payload = { 
        email: user.email, 
        role: user.role, 
        id: user.id,
        username: user.username 
      };

      const accessToken = await this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_KEY'),
        expiresIn: '15m',
      });

      const refreshToken = await this.jwtService.signAsync(
        { ...payload, countEX: 5 },
        {
          secret: this.configService.get<string>('JWT_REFRESH_KEY'),
          expiresIn: '7d',
        },
      );

      // 💡 التعديل 2: استخدام instanceToPlain لتطبيق @Exclude() بدلاً من الحذف اليدوي
      const safeUser = instanceToPlain(user) as User;

      return {
        user: safeUser,
        accessToken,
        refreshToken,
        message: 'Login successful',
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new InternalServerErrorException('Error during login');
    }
  }

  // 🔵 FORGOT PASSWORD
  async forgotPassword(emailDto: ForgotPasswordDto): Promise<MessageResponse> {
    // ... بدون تغيير
    try {
      const user = await this.userRepo.findOne({
        where: { email: emailDto.email },
      });
      
      if (!user) {
        throw new NotFoundException('Email not found');
      }

      const code = Math.floor(100000 + Math.random() * 900000);
      const hashedCode = await bcrypt.hash(code.toString(), 10);

      // Set expiration time (10 minutes)
      const expirationTime = new Date(Date.now() + 10 * 60 * 1000);
      
      await this.userRepo.update(
        { email: emailDto.email }, 
        { 
          verificationCode: hashedCode,
          verificationCodeExpires: expirationTime 
        }
      );

      // إرسال الإيميل
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: this.configService.get<string>('NODEMAILER_USERNAME'),
          pass: this.configService.get<string>('NODEMAILER_PASSWORD'),
        },
      });

      const htmlMsg = `
        <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f5f5f5;">
          <h2 style="color: #333;">🔐 Reset Your Password</h2>
          <p>Hello ${user.username},</p>
          <p>Your verification code is:</p>
          <h3 style="color: #007bff;">${code}</h3>
          <p>This code will expire in a few minutes. Please don't share it with anyone.</p>
          <br/>
          <p>Best regards,<br/>Your App Team</p>
        </div>
      `;

      await transporter.sendMail({
        from: `"Your App" <${this.configService.get<string>('NODEMAILER_USERNAME')}>`,
        to: emailDto.email,
        subject: 'Reset Password Verification Code',
        html: htmlMsg,
      });

      return { message: `Verification code sent to ${emailDto.email}` };
      
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException('Error sending verification code');
    }
  }

  // 🟢 VERIFY RESET CODE
  async verifyResetPasswordCode(verifyDto: VerifyResetPasswordCodeDto): Promise<MessageResponse> {
    // ... بدون تغيير
    try {
      const user = await this.userRepo.findOne({
        where: { email: verifyDto.email },
        select: ['email', 'verificationCode', 'verificationCodeExpires'],
      });

      if (!user || !user.verificationCode) {
        throw new ConflictException('Invalid or expired code');
      }

      // Check if code expired
      if (user.verificationCodeExpires && new Date() > user.verificationCodeExpires) {
        await this.userRepo.update(
          { email: verifyDto.email }, 
          { verificationCode: '', verificationCodeExpires: null }
        );
        throw new ConflictException('Code has expired');
      }

      const isMatch = await bcrypt.compare(verifyDto.code, user.verificationCode);
      if (!isMatch) {
        throw new ConflictException('Invalid code');
      }

      // Clear the code after successful verification
      await this.userRepo.update(
        { email: verifyDto.email }, 
        { verificationCode: '', verificationCodeExpires: null }
      );

      return { message: 'Code verified successfully' };
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      throw new InternalServerErrorException('Error verifying code');
    }
  }

  // 🟠 RESET PASSWORD
  async newPassword(newPassDto: NewPasswordDto): Promise<MessageResponse> {
    try {
      const user = await this.userRepo.findOne({
        where: { email: newPassDto.email },
      });
      
      if (!user) {
        throw new NotFoundException('User not found');
      }

      const newPassword = await bcrypt.hash(newPassDto.newPassword, 12);
      await this.userRepo.update(
        { email: newPassDto.email }, 
        { 
          password: newPassword,
          // 💡 التعديل 3: مسح الرمز وتاريخ انتهائه بعد تحديث كلمة المرور (ضروري)
          verificationCode: '',
          verificationCodeExpires: null,
        }
      );

      return { message: 'Password updated successfully' };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException('Error resetting password');
    }
  }

  // 🔄 REFRESH TOKEN
  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<RefreshTokenResponse> {
    // ... بدون تغيير
    try {
      let payload: any;
      try {
        payload = await this.jwtService.verifyAsync(refreshTokenDto.refreshToken, {
          secret: this.configService.get<string>('JWT_REFRESH_KEY'),
        });
      } catch {
        throw new UnauthorizedException('Refresh token expired or invalid');
      }

      if (!payload || payload.countEX <= 0) {
        throw new UnauthorizedException('Invalid refresh token, please sign in again');
      }

      const user = await this.userRepo.findOne({ 
        where: { email: payload.email } 
      });
      
      if (!user) {
        throw new NotFoundException('User not found');
      }

      const newPayload = { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        username: user.username 
      };

      const accessToken = await this.jwtService.signAsync(newPayload, {
        secret: this.configService.get<string>('JWT_KEY'),
        expiresIn: '15m',
      });

      const refreshToken = await this.jwtService.signAsync(
        {
          ...newPayload,
          countEX: payload.countEX - 1,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_KEY'),
          expiresIn: '7d',
        },
      );

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException || error instanceof NotFoundException) {
        throw error;
      }
      throw new InternalServerErrorException('Error refreshing token');
    }
  }
}