import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EmailModule } from '../email/email.module';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from '../../security/jwt/jwt.strategy';
import { LocalStrategy } from '../../security/local/local.strategy';
import { AuthResolver } from './auth.resolver';
import { UserModule } from '../user/user.module';

@Module({
  providers: [AuthResolver, AuthService, LocalStrategy, JwtStrategy],
  imports: [
    PassportModule,
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('secret'),
        signOptions: {
          expiresIn: configService.get<string>('jwt.ttl'),
        },
      }),
    }),
    EmailModule,
    UserModule,
  ],
  exports: [AuthService],
})
export class AuthModule {}