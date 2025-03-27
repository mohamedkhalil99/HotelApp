import { Field,ObjectType } from '@nestjs/graphql';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@ObjectType() // GraphQL ObjectType decorator
@Entity() // TypeORM Entity decorator
export class Hotel 
{
  @PrimaryGeneratedColumn()
  @Field()
  id:number

  @Column()
  @Field()
  name: string;

  @Column()
  @Field()
  city:string;

  @Column()
  @Field({nullable:true})
  description: string;

  @Column()
  @Field()
  availableRooms: number;
  
  @Column()
  @Field()
  rating:number;

  @Column()
  @Field()
  hasWifi:string;

  @Column()
  @Field()
  hasParking:string;

  @Column()
  @Field({nullable:true})
  priceRange: number;
}
// {
//   @Field(() => Int) // GraphQL field for ID
//   @PrimaryGeneratedColumn()
//   id: number;

//   @Field() 
//   @Column()
//   name: string;

//   @Field(() => Int, { nullable: true })
//   @Column({ nullable: true })
//   totalRooms: number;

//   @Field(() => Int) 
//   @Column()
//   availableRooms: number;

//   @Field({ nullable: true }) 
//   @Column({ nullable: true })
//   description: string;

//   @Field(() => Int, { nullable: true })
//   @Column({ nullable: true })
//   priceRange: number;

//   @Field({ nullable: true })
//   @Column({ nullable: true })
//   type: string;
// }