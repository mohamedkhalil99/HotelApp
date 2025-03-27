import {InputType, PartialType } from '@nestjs/graphql';
import { AddHotelDto } from './createHotel.dto';

@InputType()
export class UpdateHotelDto extends PartialType(AddHotelDto) {}