import { Module } from '@nestjs/common';
import { HotelModule } from './hotel/hotel.module';
import { GraphQLModule } from '@nestjs/graphql';
import { join } from 'path';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UserMeModule } from './user-me/user-me.module';
import { UserModule } from './userForAdmin/user.module';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule.forRoot({isGlobal: true}),
    JwtModule.register({
      global: true,
      secret: process.env.JWT_KEY,
      signOptions: { expiresIn: '2d' },
    }),
    TypeOrmModule.forRoot({
    type: 'mariadb',
    host: '127.0.0.1',
    port: 3306,
    username: 'root',
    password: '',
    database: 'hotels',
    entities: ['dist/**/*.entity.js'],
    synchronize: true,//false while building 
  })
  ,GraphQLModule.forRoot<ApolloDriverConfig>({
    driver: ApolloDriver,
    autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
    context: ({ req, res }) => ({ req, res }),
  }),
  HotelModule,
  AuthModule,
  UserMeModule,
  UserModule
],
  controllers: [],
  providers: [],
})
export class AppModule {}
