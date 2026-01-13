import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import bcrypt from 'bcrypt';
import type { StringValue } from 'ms';
import { Model } from 'mongoose';
import { LoginUserDto } from './dto/login-user.dto';
import { AuthTokensDto } from './dto/auth-tokens.dto';
import { UserRole } from './enums/user-role.enum';
import { AppConfig } from '../config/configuration';
import { RegisterUserDto } from './dto/register-user.dto';
import { User, UserDocument } from 'src/user/schemas/user.schema';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService<AppConfig>,
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
  ) {}

  test(): Promise<boolean> {
    return Promise.resolve(true);
  }

  async adminLogin(dto: LoginUserDto): Promise<AuthTokensDto> {
    const adminConfig = this.configService.get('admin', { infer: true });
    if (!adminConfig) {
      throw new Error('Admin config missing');
    }

    const isEmailValid = dto.email === adminConfig.email;
    const isPasswordValid = await bcrypt.compare(
      dto.password,
      adminConfig.passwordHash,
    );

    if (!isEmailValid || !isPasswordValid) {
      throw new UnauthorizedException('Invalid admin credentials');
    }

    return this.generateTokens('admin', UserRole.ADMIN);
  }

  async adminRefreshToken(refreshToken: string): Promise<AuthTokensDto> {
    const jwtConfig = this.configService.get('jwt', { infer: true });
    if (!jwtConfig) {
      throw new Error('JWT config missing');
    }

    try {
      const payload = this.jwtService.verify<{
        sub: string;
        role: UserRole;
      }>(refreshToken, {
        secret: jwtConfig.refreshSecret,
      });

      if (payload.role !== UserRole.ADMIN) {
        throw new UnauthorizedException('Invalid admin refresh token');
      }

      return this.generateTokens(payload.sub, UserRole.ADMIN);
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async userRefreshToken(refreshToken: string): Promise<AuthTokensDto> {
    const jwtConfig = this.configService.get('jwt', { infer: true });
    if (!jwtConfig) {
      throw new Error('JWT config missing');
    }

    try {
      const payload = this.jwtService.verify<{
        sub: string;
        role: UserRole;
      }>(refreshToken, {
        secret: jwtConfig.refreshSecret,
      });

      if (payload.role !== UserRole.USER) {
        throw new UnauthorizedException('Invalid user refresh token');
      }

      return this.generateTokens(payload.sub, UserRole.USER);
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async userRegister(dto: RegisterUserDto): Promise<Omit<User, 'password'>> {
    const existingUser = await this.userModel.findOne({ email: dto.email });
    if (existingUser) {
      throw new BadRequestException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(dto.password, 12);
    const createdUser = new this.userModel({
      ...dto,
      password: hashedPassword,
      role: UserRole.USER,
    });

    const savedUser = await createdUser.save();
    const { password, ...userWithoutPassword } = savedUser.toObject();
    return userWithoutPassword;
  }

  async userLogin(dto: LoginUserDto): Promise<AuthTokensDto> {
    const existingUser = await this.userModel.findOne({ email: dto.email });
    if (!existingUser) {
      throw new NotFoundException('Email not found');
    }

    const isPasswordValid = await bcrypt.compare(
      dto.password,
      existingUser.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    return this.generateTokens(existingUser._id.toString(), UserRole.USER);
  }

  private generateTokens(id: string, role: UserRole): AuthTokensDto {
    const jwtConfig = this.configService.get('jwt', { infer: true });
    if (!jwtConfig) {
      throw new Error('JWT config missing');
    }

    const payload = { sub: id, role };

    const accessToken = this.jwtService.sign(payload, {
      secret: jwtConfig.accessSecret,
      expiresIn: this.parseExpiresIn(jwtConfig.accessExpiresIn),
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: jwtConfig.refreshSecret,
      expiresIn: this.parseExpiresIn(jwtConfig.refreshExpiresIn),
    });

    return { accessToken, refreshToken };
  }

  private parseExpiresIn(value: string): StringValue | number {
    if (/^\d+$/.test(value)) {
      return Number(value);
    }

    if (/^\d+(s|m|h|d)$/.test(value)) {
      return value as StringValue;
    }

    throw new Error(
      `Invalid JWT expires format: ${value}. Use 15m, 7d, 3600 etc.`,
    );
  }
}
