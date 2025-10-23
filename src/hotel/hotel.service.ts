import { Injectable, NotFoundException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { AddHotelDto } from './dto/createHotel.dto';
import { UpdateHotelDto } from './dto/updateHotel.dto';
import { Hotel } from './hotel.entity';

@Injectable()
export class HotelService {
  constructor(@InjectRepository(Hotel) private readonly hotelRepo: Repository<Hotel>) {}

  async addHotel(hotelInput: AddHotelDto): Promise<Hotel> {
    const hotel = this.hotelRepo.create(hotelInput);
    return this.hotelRepo.save(hotel);
  }

  async allHotels(): Promise<Hotel[]> {
    const hotels = await this.hotelRepo.find();
    if (!hotels.length) throw new NotFoundException('No hotels to show');
    return hotels;
  }

  async getHotelsByCity(city: string): Promise<Hotel[]> {
    const hotels = await this.hotelRepo.find({ where: { city } });
    if (!hotels.length) throw new NotFoundException('No hotels found in this city');
    return hotels;
  }

  async getHotel(id: number): Promise<Hotel> {
    const hotel = await this.hotelRepo.findOne({ where: { id } });
    if (!hotel) throw new NotFoundException('Hotel not found');
    return hotel;
  }

  async updateHotel(id: number, updateHotelInput: UpdateHotelDto): Promise<Hotel> {
    const hotel = await this.hotelRepo.findOne({ where: { id } });
    if (!hotel) throw new NotFoundException('No hotel to update');

    const updated = { ...hotel, ...updateHotelInput };
    return this.hotelRepo.save(updated);
  }

  async deleteHotel(id: number): Promise<string> {
    const hotel = await this.hotelRepo.findOne({ where: { id } });
    if (!hotel) throw new NotFoundException('No hotel to delete');

    await this.hotelRepo.delete(id);
    return 'Hotel deleted successfully';
  }
}