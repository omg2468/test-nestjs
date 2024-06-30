import { PrismaService } from './../prisma/prisma.service';
import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable({})
export class AuthService {
  constructor(private PrismaService: PrismaService) {}
  async signin(dto: AuthDto) {
    const user = await this.PrismaService.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Credentials incorrect');

    const pwMath = await argon.verify(user.hash, dto.password);

    if (!pwMath) throw new ForbiddenException('Credentials incorrect');

    delete user.hash;

    return user;
  }

  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);

      console.log(hash);

      const user = await this.PrismaService.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      return { user };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }
}
