import { Injectable } from '@nestjs/common';
import { PrismaService } from '../PrismaService';
import { Prisma } from '@prisma/client';

@Injectable()
export class UserRepository {
  
  constructor (
    private prisma: PrismaService,
  ) {}

  async create (data: Prisma.UserUncheckedCreateInput) {
    return this.prisma.user.create({ data });
  }

  async find (where: Prisma.UserWhereInput) {
    return this.prisma.user.findFirst({ where });
  }

  async deleteById (id: string) {
    return this.prisma.user.delete({
      where: { id },
    });
  }

  async updateById (id: string, data: Prisma.UserUncheckedUpdateInput) {
    return this.prisma.user.update({
      where: { id },
      data,
    });
  }
}