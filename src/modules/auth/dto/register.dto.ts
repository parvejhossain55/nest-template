import {
  IsEmail,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

// Password must contain at least one uppercase, one lowercase, one digit,
// and one special character (!@#$%^&*()_+\-=\[\]{};':"\\\\|,.<>/?]).
const PASSWORD_COMPLEXITY = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\\\|,.<>/?]).+$/;

export class RegisterDto {
  @IsEmail()
  email: string;

  // 72 is bcrypt's hard byte limit; beyond it the input is silently truncated.
  @IsString()
  @MinLength(8)
  @MaxLength(72)
  @Matches(PASSWORD_COMPLEXITY, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  password: string;

  @IsString()
  @IsOptional()
  name?: string;
}
