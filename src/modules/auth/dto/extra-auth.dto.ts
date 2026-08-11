import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';

export class VerifyEmailDto {
  @IsString()
  token: string;
}

export class ForgotPasswordDto {
  @IsEmail()
  email: string;
}

export class ResetPasswordDto {
  @IsString()
  token: string;

  @IsString()
  @MinLength(8)
  newPassword: string;
}

export class Enable2faDto {
  @IsString()
  code: string;
}

export class Verify2faDto {
  @IsString()
  twoFactorToken: string;

  @IsString()
  code: string;
}
