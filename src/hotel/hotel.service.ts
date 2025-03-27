import { Injectable, NotFoundException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { AddHotelDto } from './dto/createHotel.dto';
import { Hotel } from './hotel.entity';
import { Args } from '@nestjs/graphql';
import { UpdateHotelDto } from './dto/updateHotel.dto';

@Injectable()
export class HotelService 
{
  constructor(@InjectRepository(Hotel) private readonly hotel:Repository<Hotel>,){}
  
  async addHotel(hotelInput:AddHotelDto):Promise<Hotel>
  {
    const hotel =await this.hotel.create(hotelInput);
    return this.hotel.save(hotel);
  }
  
  async allHotels():Promise<Hotel[]>
  {
    const hotels= await this.hotel.find();
    if(!hotels){throw new NotFoundException('No Hotels To Show');}
    return hotels;
  }
  
  async getHotelsByCity(@Args('city') city: string): Promise<Hotel[]> 
  {
    const hotels = await this.hotel.find({where:{city}});
    if (!hotels) {throw new NotFoundException('No Hotel In This City');}
    return hotels;
  }
      
  async getHotel(@Args('id') id: number): Promise<Hotel> 
  {
    const hotel = await this.hotel.findOneByOrFail({id});
    if (!hotel) {throw new NotFoundException('No Hotel To Show');}
    return hotel;
  }
      
  async updateHotel(@Args('id')id:number ,@Args('updateHotelInput') updateHotelInput: UpdateHotelDto): Promise<Hotel> 
  {
    const hotel= await this.hotel.findOne({where:{id:id}});
    if(!hotel){throw new NotFoundException('No Hotel To Update');}
    return this.hotel.save({...hotel,...updateHotelInput});
  }

  async deleteHotel(@Args('id') id: number): Promise<string> 
  {
    const hotel= await this.hotel.findOne({where:{id:id}});
    if(!hotel){throw new NotFoundException('No Hotel To Delete');}
    await this.hotel.delete(id);
    return 'Hotel Deleted'
  }
}