import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Request } from "express";
import { ApiKeysService } from "../../api-keys/api-keys.service";
import { SCOPES_KEY } from "../decorators/require-scopes.decorator";

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly apiKeysService: ApiKeysService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    const rawKey = request.headers["x-api-key"];
    if (!rawKey || typeof rawKey !== "string") {
      throw new UnauthorizedException("Missing x-api-key header");
    }

    // Authenticate – throws UnauthorizedException for any invalid state
    const principal = await this.apiKeysService.authenticate(rawKey);

    // Check scopes declared on the handler/class (defaults to [] = no access)
    const requiredScopes: string[] =
      this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];

    if (requiredScopes.length === 0) {
      // No scopes declared means the route is not open to API keys by default
      throw new ForbiddenException("Route does not accept API key access");
    }

    const hasAllScopes = requiredScopes.every((s) =>
      principal.scopes.includes(s),
    );

    if (!hasAllScopes) {
      throw new ForbiddenException(
        "API key lacks the required scopes for this endpoint",
      );
    }

    // Attach principal to request for downstream access
    request.apiKey = principal;

    return true;
  }
}
