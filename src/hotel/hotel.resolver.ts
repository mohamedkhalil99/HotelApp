import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { HotelService } from './hotel.service';
import { AddHotelDto } from './dto/createHotel.dto';
import { Hotel } from './hotel.entity';
import { UpdateHotelDto } from './dto/updateHotel.dto';

@Resolver(()=>Hotel)
export class HotelResolver 
{
    constructor(private hotelService:HotelService){}

    @Mutation(()=>Hotel)
    addHotel(@Args('hotelInput') hotelInput:AddHotelDto):Promise<Hotel>
    {
        return this.hotelService.addHotel(hotelInput);
    }

    @Query(()=>[Hotel])
    allHotels():Promise<Hotel[]>
    {
        return this.hotelService.allHotels();
    }

    @Query(()=>[Hotel])
    getHotelsByCity(@Args('city') city: string):Promise<Hotel[]>
    {
        return this.hotelService.getHotelsByCity(city)
    }
    
    @Query(()=>Hotel)
    getHotel(@Args('id') id: number):Promise<Hotel>
    {
        return this.hotelService.getHotel(id)
    }

    @Mutation(()=>Hotel)
    updateHotel(@Args('id')id:number,@Args('updateHotelInput') updateHotelInput:UpdateHotelDto):Promise<Hotel>
    {
        return this.hotelService.updateHotel(id,updateHotelInput);
    }

    @Mutation(()=>String)
    deleteHotel(@Args('id')id:number):Promise<string>
    {
        return this.hotelService.deleteHotel(id);
    }
}