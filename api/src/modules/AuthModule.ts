import { Module } from '@nestjs/common';
import { AuthController } from '../api/controllers/AuthController';
import { AuthService } from '../api/services/AuthService';
import { LocalStrategy } from '../security/LocalStrategy';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtStrategy } from '../security/JwtStrategy';

@Module({
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  imports: [
    JwtModule.registerAsync({
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('secret'),
        signOptions: {
          expiresIn: configService.get<string>('jwt.ttl'),
        },
      }),
    })
  ],
  exports: [AuthService],
})
export class AuthModule {}