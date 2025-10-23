import { Field, InputType, Float, Int } from '@nestjs/graphql';
import { IsNumber, IsOptional, IsString, IsBoolean, Min, Max } from 'class-validator';

@InputType()
export class AddHotelDto {
  @IsString()
  @Field()
  name: string;

  @IsString()
  @Field()
  city: string;

  @IsOptional()
  @IsString()
  @Field({ nullable: true })
  description?: string;

  @IsNumber()
  @Min(0)
  @Field(() => Int)
  availableRooms: number;

  @IsNumber()
  @Min(0)
  @Max(5)
  @Field(() => Float)
  rating: number;

  @IsBoolean()
  @Field()
  hasWifi: boolean;

  @IsBoolean()
  @Field()
  hasParking: boolean;

  @IsOptional()
  @IsNumber()
  @Field(() => Float, { nullable: true })
  priceRange?: number;
}