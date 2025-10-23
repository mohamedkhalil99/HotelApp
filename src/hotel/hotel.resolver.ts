import { Args, Int, Mutation, Query, Resolver } from '@nestjs/graphql';
import { HotelService } from './hotel.service';
import { AddHotelDto } from './dto/createHotel.dto';
import { UpdateHotelDto } from './dto/updateHotel.dto';
import { Hotel } from './hotel.entity';
import { UseGuards } from '@nestjs/common';
import { AuthGuard } from 'src/userForAdmin/guards/auth.guard';
import { Roles } from 'src/userForAdmin/decorators/roles.decorator';
import { UserRole } from 'src/userForAdmin/entities/user.entity';

@UseGuards(AuthGuard)
@Resolver(() => Hotel)
export class HotelResolver {
  constructor(private readonly hotelService: HotelService) {}

  // Desc: User can create a new hotel
  // Mutation: addHotel(hotelInput: AddHotelDto)
  // Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Mutation(() => Hotel)
  addHotel(@Args('hotelInput') hotelInput: AddHotelDto): Promise<Hotel> {
    return this.hotelService.addHotel(hotelInput);
  }

  // Desc: Get all hotels
  // Query: allHotels
  // Access: Public
  @Query(() => [Hotel])
  allHotels(): Promise<Hotel[]> {
    return this.hotelService.allHotels();
  }

  // Desc: Get hotels filtered by city
  // Query: getHotelsByCity(city: String)
  // Access: Public
  @Query(() => [Hotel])
  getHotelsByCity(@Args('city', { type: () => String }) city: string): Promise<Hotel[]> {
    return this.hotelService.getHotelsByCity(city);
  }

  // Desc: Get a single hotel by ID
  // Query: getHotel(id: Int)
  // Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Query(() => Hotel)
  getHotel(@Args('id', { type: () => Int }) id: number): Promise<Hotel> {
    return this.hotelService.getHotel(id);
  }

  // Desc: Update hotel info by ID
  // Mutation: updateHotel(id: Int, updateHotelInput: UpdateHotelDto)
  // Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Mutation(() => Hotel)
  updateHotel(@Args('id', { type: () => Int }) id: number,
    @Args('updateHotelInput') updateHotelInput: UpdateHotelDto): Promise<Hotel> {
    return this.hotelService.updateHotel(id, updateHotelInput);
  }

  // Desc: Delete hotel by ID
  // Mutation: deleteHotel(id: Int)
  // Access: Private (admin only)
  @Roles([UserRole.ADMIN])
  @Mutation(() => String)
  deleteHotel(@Args('id', { type: () => Int }) id: number): Promise<string> {
    return this.hotelService.deleteHotel(id);
  }
}