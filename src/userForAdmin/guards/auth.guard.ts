import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Roles } from '../decorators/roles.decorator';
import { GqlExecutionContext } from '@nestjs/graphql';

interface JwtPayload {
  sub: string;
  email: string;
  role: 'admin' | 'user';
  iat?: number;
  exp?: number;
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private reflector: Reflector, private jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(Roles, [
      context.getHandler(),
      context.getClass(),
    ]);

    // لو مفيش role محدد للسياق، يبقى نسمح عادي
    if (!requiredRoles) return true;

    // جلب GraphQL context
    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('No Authorization header found');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      const payload = this.jwtService.verify<JwtPayload>(token, {
        secret: process.env.JWT_KEY,
      });

      req.user = payload;

      // لو اليوزر عنده أحد الأدوار المطلوبة، نسمحله
      return requiredRoles.some((role) => payload.role === role);
    } 
    catch {
      throw new UnauthorizedException('Invalid or expired token');  
    } 
  }
}