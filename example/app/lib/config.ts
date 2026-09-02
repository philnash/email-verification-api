import * as z from "zod";
import { env } from "node:process";

const ConfigSchema = z.object({
  SESSION_SECRET: z.string().min(1),
  JWT_SECRET: z.string().min(1),
  RESEND_API_KEY: z.string().min(1),
  RESEND_EMAIL_FROM: z.email().min(1),
});

const config = ConfigSchema.parse(env);

export const sessionSecret = config.SESSION_SECRET;
export const resendApiKey = config.RESEND_API_KEY;
export const fromEmail = config.RESEND_EMAIL_FROM;
export const jwtSecret = config.JWT_SECRET;
