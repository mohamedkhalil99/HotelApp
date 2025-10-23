import { Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { instanceToPlain } from "class-transformer";
import { UpdateUserDto } from "src/userForAdmin/dto/updateUser.dto";
import { User } from "src/userForAdmin/entities/user.entity";
import { Repository } from "typeorm";
import * as bcrypt from "bcrypt"

@Injectable()
export class UserMeService {
  constructor(@InjectRepository(User) private userRepo: Repository<User>) {}

  private async getUserById(userId: number): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async getSelf(userId: number): Promise<User> {
    const user = await this.getUserById(userId);
    return instanceToPlain(user) as User;
  }

  async updateSelf(userId: number, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.getUserById(userId);

    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }

    Object.assign(user, updateUserDto);
    const updatedUser = await this.userRepo.save(user);
    return instanceToPlain(updatedUser) as User;
  }

  async deleteSelf(userId: number): Promise<string> {
    const user = await this.getUserById(userId);
    await this.userRepo.delete(user.id);
    return 'Account deleted successfully';
  }
}