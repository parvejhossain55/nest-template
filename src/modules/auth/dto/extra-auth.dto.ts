import { IsEmail, IsString, Matches, MaxLength, MinLength } from 'class-validator';

// Password must contain at least one uppercase, one lowercase, one digit,
// and one special character (!@#$%^&*()_+\-=\[\]{};':"\\\\|,.<>/?]).
const PASSWORD_COMPLEXITY = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\\\|,.<>/?]).+$/;

export class VerifyEmailDto {
  @IsString()
  token: string;
}

export class ResendVerificationDto {
  @IsEmail()
  email: string;
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
  @MaxLength(72)
  @Matches(PASSWORD_COMPLEXITY, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  newPassword: string;
}

export class ChangePasswordDto {
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  oldPassword: string;

  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @Matches(PASSWORD_COMPLEXITY, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  newPassword: string;
}

