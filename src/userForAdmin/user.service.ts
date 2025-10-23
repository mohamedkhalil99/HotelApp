import { ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { User, UserRole } from "./entities/user.entity";
import { CreateUserDto } from "./dto/createUser.dto";
import * as bcrypt from "bcrypt";
import { UpdateUserDto } from "./dto/updateUser.dto";
import { Repository } from "typeorm";
import { instanceToPlain } from "class-transformer";

@Injectable()
export class UserService {
  constructor(@InjectRepository(User) private userRepo: Repository<User>) {}

  async addUser(createUserDto: CreateUserDto): Promise<User> {
    const existing = await this.userRepo.findOne({ where: { email: createUserDto.email } });
    if (existing) throw new ConflictException('Email already exists');

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = this.userRepo.create({
      ...createUserDto,
      password: hashedPassword,
      role: createUserDto.role || UserRole.USER,
    });

    return this.userRepo.save(newUser);
  }

  async allUsers(): Promise<User[]> {
    const users = await this.userRepo.find();
    if (!users || users.length === 0) throw new ConflictException('No users found');
    return instanceToPlain(users) as User[];
  }

  async getUserById(id: number): Promise<User> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return instanceToPlain(user) as User;
  }

  async updateUserAsAdmin(id: number, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.getUserById(id);

    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }

    Object.assign(user, updateUserDto);
    return this.userRepo.save(user);
  }

  async deleteUserAsAdmin(id: number): Promise<string> {
    const user = await this.getUserById(id);
    await this.userRepo.delete(user.id);
    return `User with ID ${id} has been deleted successfully`;
  }
}