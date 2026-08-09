import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/modules/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService, private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('jwt.accessSecret') || '',
    });
  }

  async validate(payload: any) {
    const user = await this.prisma.user.findFirst({ 
      where: { id: payload.sub, deletedAt: null },
      select: { id: true, email: true, role: true, isActive: true }
    });
    if (!user) throw new UnauthorizedException();

    return { id: user.id, email: user.email, role: user.role };
  }
}
