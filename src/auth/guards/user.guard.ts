import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { ConfigService } from '@nestjs/config';
import { UserRole } from '../enums/user-role.enum';
import { AppConfig } from '../../config/configuration';

@Injectable()
export class UserGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService<AppConfig>,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    const authHeader = request.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException(
        'Missing or invalid Authorization header',
      );
    }

    const token = authHeader.split(' ')[1];

    try {
      const jwtConfig = this.configService.get('jwt', { infer: true });
      if (!jwtConfig) {
        throw new UnauthorizedException('JWT configuration missing');
      }

      const decoded = this.jwtService.verify(token, {
        secret: jwtConfig.accessSecret,
      });

      if (!decoded || decoded.role !== UserRole.USER) {
        throw new ForbiddenException('Access denied: Users only');
      }

      request['user'] = decoded;

      return true;
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
