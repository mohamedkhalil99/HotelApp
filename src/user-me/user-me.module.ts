import { Module } from '@nestjs/common';
import { UserMeResolver } from './user-me.resolver';
import { UserMeService } from './user-me.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/userForAdmin/entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserMeService, UserMeResolver],
})
export class UserMeModule {}