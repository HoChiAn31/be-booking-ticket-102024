import { ApiProperty } from '@nestjs/swagger';

export class FilterUserDto {
  page: string;

  items_per_page: string;

  search: string;
}
