import { Module } from '@nestjs/common';
import { HotelService } from './hotel.service';
import { HotelResolver } from './hotel.resolver';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Hotel} from './hotel.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Hotel])], // Register entities
  providers: [HotelService, HotelResolver],
  exports: [HotelService],})
export class HotelModule {}
