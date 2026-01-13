import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { LoginUserDto } from './dto/login-user.dto';
import { AdminGuard } from './guards/admin.guard';
import { RegisterUserDto } from './dto/register-user.dto';
import { RefreshTokensDto } from './dto/refresh-token.dto';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('test')
  @ApiOperation({ summary: 'Test endpoint' })
  @ApiResponse({ status: 200, description: 'Returns true', type: Boolean })
  test(): Promise<boolean> {
    return this.authService.test();
  }

  @Post('admin/login')
  @ApiOperation({ summary: 'Login Admin' })
  @ApiResponse({
    status: 200,
    description: 'Returns access and refresh tokens',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  adminLogin(@Body() dto: LoginUserDto) {
    return this.authService.adminLogin(dto);
  }

  @Get('dashboard')
  @ApiOperation({ summary: 'Admin dashboard' })
  @ApiBearerAuth()
  @ApiResponse({ status: 200, description: 'Returns welcome message' })
  @UseGuards(AdminGuard)
  getDashboard() {
    return { message: 'Welcome Admin!' };
  }

  @Post('user/register')
  @ApiOperation({ summary: 'User Register' })
  @ApiResponse({
    status: 201,
    description: 'New user created successfully',
    schema: {
      example: {
        id: '64b1f2c8d1e9f0a5a6b12345',
        name: 'Akhil',
        email: 'ak@gmail.com',
        age: 25,
        gender: 'male',
      },
    },
  })
  userRegister(@Body() dto: RegisterUserDto) {
    return this.authService.userRegister(dto);
  }

  @Post('user/login')
  @ApiOperation({ summary: 'Login User' })
  @ApiResponse({
    status: 200,
    description: 'Returns access and refresh tokens',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  userLogin(@Body() dto: LoginUserDto) {
    return this.authService.userLogin(dto);
  }

  @Post('admin/refresh-token')
  @ApiOperation({ summary: 'Refresh Admin Token' })
  @ApiResponse({
    status: 200,
    description: 'Returns new access and refresh tokens',
  })
  adminRefreshToken(@Body() dto: RefreshTokensDto) {
    return this.authService.adminRefreshToken(dto.token);
  }

  @Post('user/refresh-token')
  @ApiOperation({ summary: 'Refresh User Token' })
  @ApiResponse({
    status: 200,
    description: 'Returns new access and refresh tokens',
  })
  userRefreshToken(@Body() dto: RefreshTokensDto) {
    return this.authService.userRefreshToken(dto.token);
  }
}
