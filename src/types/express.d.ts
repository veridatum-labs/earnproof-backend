import { AuthTokenPayload } from "../auth/auth.types";
import { ApiKeyPrincipal } from "../api-keys/api-keys.service";

declare module "express-serve-static-core" {
  interface Request {
    user?: AuthTokenPayload;
    apiKey?: ApiKeyPrincipal;
  }
}
