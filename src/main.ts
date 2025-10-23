import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
//   const dataSource = app.get(DataSource);
//   await createAdminUser(dataSource);  
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();