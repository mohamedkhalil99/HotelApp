import { Field, InputType } from "@nestjs/graphql";
import { IsNumber, IsString } from "class-validator";

@InputType()
export class AddHotelDto
{
  @IsNumber()
  @Field()
  id:number

  @IsString()
  @Field()
  name: string;

  @IsString()
  @Field()
  city:string;

  @IsString()
  @Field({nullable:true})
  description: string;

  @IsNumber()
  @Field()
  availableRooms: number;
  
  @IsNumber()
  @Field()
  rating:number;

  @IsString()
  @Field()
  hasWifi:string;

  @IsString()
  @Field()
  hasParking:string;

  @IsNumber()
  @Field({nullable:true})
  priceRange: number;
}