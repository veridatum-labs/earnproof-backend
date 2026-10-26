import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString, MaxLength, MinLength } from "class-validator";

export class RejectRoleChangeRequestDto {
  @ApiProperty({
    description: "Reason for rejecting the role change request.",
    example: "Insufficient justification provided; pending further access review.",
    minLength: 3,
    maxLength: 512,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(512)
  reason!: string;
}
