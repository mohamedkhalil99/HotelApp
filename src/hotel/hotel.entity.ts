import { Field, Float, Int, ObjectType } from '@nestjs/graphql';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@ObjectType() // GraphQL ObjectType decorator
@Entity() // TypeORM Entity decorator
export class Hotel 
{
  @PrimaryGeneratedColumn()
  @Field(() => Int)
  id: number;

  @Column()
  @Field()
  name: string;

  @Column()
  @Field()
  city: string;

  @Column({ nullable: true })
  @Field({ nullable: true })
  description?: string;

  @Column({ type: 'int' })
  @Field(() => Int)
  availableRooms: number;

  @Column({ type: 'float', default: 0 })
  @Field(() => Float)
  rating: number;

  @Column({ default: false })
  @Field()
  hasWifi: boolean;

  @Column({ default: false })
  @Field()
  hasParking: boolean;

  @Column({ type: 'float', nullable: true })
  @Field(() => Float, { nullable: true })
  priceRange?: number;
}