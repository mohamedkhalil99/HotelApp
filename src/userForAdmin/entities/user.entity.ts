import { Field, ObjectType, registerEnumType } from "@nestjs/graphql";
import { Exclude } from "class-transformer";
import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

export enum UserRole {
  ADMIN = 'admin',
  USER = 'user',
}

registerEnumType(UserRole, { name: 'UserRole' });

@ObjectType()
@Entity('users')
export class User {
  @Field()
  @PrimaryGeneratedColumn()
  id: number;

  @Field()
  @Column()
  username: string;

  @Field()
  @Column({ unique: true })
  email: string;

  // @Field()
  @Exclude()
  @Column({ length: 255})
  password: string;

  @Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
  @Field(() => UserRole)
  role: UserRole;

  @Exclude()
  @Column({ name: 'verification_code', nullable: true })
  verificationCode?: string;

  @Exclude()
  @Column({ name: 'verification_code_expires', nullable: true })
  verificationCodeExpires?: Date
}