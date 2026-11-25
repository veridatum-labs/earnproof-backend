import { Injectable, NestMiddleware, BadRequestException } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';

const ALLOWED_TRANSFER_ENCODINGS = new Set(['chunked']);

@Injectable()
export class RequestFramingMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    const rawHeaders = req.rawHeaders ?? [];
    const contentLengths: string[] = [];
    const transferEncodings: string[] = [];

    for (let i = 0; i < rawHeaders.length; i += 2) {
      const name = rawHeaders[i]?.toLowerCase();
      const value = rawHeaders[i + 1] ?? '';
      if (name === 'content-length') contentLengths.push(value.trim());
      if (name === 'transfer-encoding') transferEncodings.push(value.trim());
    }

    // 1. Reject CL + TE ambiguity (RFC 9112 §6.3)
    if (contentLengths.length > 0 && transferEncodings.length > 0) {
      throw new BadRequestException('Ambiguous request framing: both Content-Length and Transfer-Encoding present');
    }

    // 2. Reject duplicate Content-Length headers or comma-separated multiple values
    if (contentLengths.length > 1) {
      throw new BadRequestException('Duplicate Content-Length headers are not permitted');
    }
    if (contentLengths.length === 1) {
      const cl = contentLengths[0];
      if (!/^\d+$/.test(cl)) {
        throw new BadRequestException('Malformed Content-Length header');
      }
    }

    // 3. Reject duplicate, obfuscated, or unsupported Transfer-Encoding values
    if (transferEncodings.length > 1) {
      throw new BadRequestException('Duplicate Transfer-Encoding headers are not permitted');
    }
    if (transferEncodings.length === 1) {
      const tokens = transferEncodings[0]
        .split(',')
        .map((t) => t.trim().toLowerCase())
        .filter(Boolean);
      if (tokens.length !== 1 || !ALLOWED_TRANSFER_ENCODINGS.has(tokens[0])) {
        throw new BadRequestException('Unsupported or obfuscated Transfer-Encoding header');
      }
    }

    next();
  }
}