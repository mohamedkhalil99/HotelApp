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

    // If no roles are required, allow access
    if (!requiredRoles) return true;

    // GraphQL context extraction
    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;

    // Retrieve token from Authorization header or cookies
    const authHeader = req.headers.authorization;
    let token: string | undefined;

    if (authHeader?.startsWith('Bearer ')) {token = authHeader.split(' ')[1];} 
    // Get token from cookies if not in header
    else if (req.cookies?.refreshToken) {token = req.cookies.refreshToken;}

    if (!token) {throw new UnauthorizedException('No Authorization header or cookie found');}

    try {
      const payload = this.jwtService.verify<JwtPayload>(token, {secret: process.env.JWT_KEY,});

      req.user = payload;

      // Check if user role is in required roles
      return requiredRoles.some((role) => payload.role === role);
    } 
    catch {throw new UnauthorizedException('Invalid or expired token');}
  }
}