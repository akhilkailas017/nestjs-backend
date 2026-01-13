import { ApiProperty } from '@nestjs/swagger';

export class RegisterUserDto {
  @ApiProperty({
    example: 'Akhil',
    description: 'User full name',
  })
  name: string;

  @ApiProperty({
    example: 'ak@gmail.com',
    description: 'User email address',
  })
  email: string;

  @ApiProperty({
    example: 25,
    description: 'User age',
  })
  age: number;

  @ApiProperty({
    example: 1234567890,
    description: 'User phone',
  })
  phone: number;

  @ApiProperty({
    example: 'male',
    description: 'User gender',
    enum: ['male', 'female'],
  })
  gender: 'male' | 'female';

  @ApiProperty({
    example: '12345',
    description: 'User password',
  })
  password: string;
}
