import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User, UserSchema } from '../user/schemas/user.schema';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/configuration';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService<AppConfig>) => {
        const jwtConfig = configService.get('jwt', { infer: true });
        if (!jwtConfig) throw new Error('JWT configuration missing');

        const parseExpiresIn = (value: string): number | any => {
          if (/^\d+$/.test(value)) return Number(value);
          if (/^\d+(s|m|h|d)$/.test(value)) return value as any;
          throw new Error(`Invalid JWT expires format: ${value}`);
        };

        return {
          secret: jwtConfig.accessSecret,
          signOptions: {
            expiresIn: parseExpiresIn(jwtConfig.accessExpiresIn),
          },
        };
      },
    }),
    ConfigModule,
  ],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}
