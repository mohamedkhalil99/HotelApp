import { DataSource } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User, UserRole } from './entities/user.entity';

export const createAdminUser = async (dataSource: DataSource) => {
  const userRepo = dataSource.getRepository(User);

  const adminEmail = process.env.ADMIN_EMAIL ?? 'example@gmail.com';
  const adminPassword = process.env.ADMIN_PASSWORD ?? '123456';
  const adminUsername = process.env.ADMIN_USERNAME ?? 'Mohamed';

  const existingAdmin = await userRepo.findOne({ where: { email: adminEmail } });

  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    const admin = userRepo.create({
      username: adminUsername,
      email: adminEmail,
      password: hashedPassword,
      role: UserRole.ADMIN,
    });

    await userRepo.save(admin);
    console.log('✅ Admin user created');
  } else {
    console.log('⚠️ Admin user already exists');
  }
};