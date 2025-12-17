import bcrypt from "bcryptjs";
import { string } from "zod";

export async function hashPassword(password: string) {
  const salt = await bcrypt.genSalt(10);

  const hash = bcrypt.hash(password, salt);

  return hash;
}

export async function checkPassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}
