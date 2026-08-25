import { IsObject } from "class-validator";
import {
  registerDecorator,
  ValidationOptions,
  ValidationArguments,
} from "class-validator";

const MAX_PAYLOAD_BYTES = 32 * 1024; // 32 KB

/**
 * Measures the maximum nesting depth of a plain object/array.
 */
function objectDepth(value: unknown, current = 0): number {
  if (value === null || typeof value !== "object") {
    return current;
  }

  const children = Array.isArray(value)
    ? value
    : Object.values(value as Record<string, unknown>);

  if (children.length === 0) {
    return current + 1;
  }

  return Math.max(...children.map((child) => objectDepth(child, current + 1)));
}

/**
 * Rejects payloads whose JSON representation exceeds 32 KB.
 */
function MaxBytes(limit: number, validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: "maxBytes",
      target: object.constructor,
      propertyName,
      constraints: [limit],
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          try {
            return Buffer.byteLength(JSON.stringify(value), "utf8") <= limit;
          } catch {
            return false;
          }
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} must not exceed ${(args.constraints[0] as number) / 1024} KB`;
        },
      },
    });
  };
}

/**
 * Rejects payloads whose nesting depth exceeds the given limit.
 */
function MaxDepth(limit: number, validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      name: "maxDepth",
      target: object.constructor,
      propertyName,
      constraints: [limit],
      options: validationOptions,
      validator: {
        validate(value: unknown) {
          return objectDepth(value) <= limit;
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} must not be nested deeper than ${args.constraints[0] as number} levels`;
        },
      },
    });
  };
}

export class VerifyCredentialDto {
  @IsObject()
  @MaxBytes(MAX_PAYLOAD_BYTES)
  @MaxDepth(5)
  credential!: Record<string, unknown>;
}
