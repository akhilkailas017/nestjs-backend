import { ApiProperty } from '@nestjs/swagger';

export class LoginUserDto {
  @ApiProperty({
    example: 'admin@gmail.com',
    description: 'Admin email address',
  })
  email: string;

  @ApiProperty({
    example: 'admin',
    description: 'Admin password',
  })
  password: string;
}
