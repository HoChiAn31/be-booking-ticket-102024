import {
  Body,
  Controller,
  Post,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register-user.dto';
import { AuthService } from './auth.service';
import { User } from 'src/user/entities/user.entity';
import { LoginUserDto } from './dto/login-user.dto';
import { ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() registerUserDto: RegisterUserDto): Promise<User> {
    // console.log('register');
    // console.log(registerUserDto);
    return this.authService.resgister(registerUserDto);
  }

  @Post('login')
  @ApiResponse({ status: 201, description: 'Login successfully' })
  @ApiResponse({ status: 401, description: 'Login fail' })
  @UsePipes(ValidationPipe)
  login(@Body() loginUserDto: LoginUserDto): Promise<any> {
    // console.log('login');
    // console.log(loginUserDto);
    return this.authService.login(loginUserDto);
  }

  @Post('refresh-token')
  refreshToken(@Body() { refreshToken }): Promise<any> {
    console.log('refresh token');
    return this.authService.refreshToken(refreshToken);
  }

  // API gửi mã OTP về email
  @Post('send-otp')
  @UsePipes(ValidationPipe)
  async sendOtp(@Body('email') email: string): Promise<string> {
    return this.authService.sendOtp(email);
  }

  // API xác nhận mã OTP
  @Post('verify-otp')
  @UsePipes(ValidationPipe)
  async verifyOtp(
    @Body('email') email: string,
    @Body('otp') otp: string,
  ): Promise<string> {
    return this.authService.verifyOtp(email, otp);
  }

  // API đặt lại mật khẩu
  @Post('reset-password')
  @UsePipes(ValidationPipe)
  async resetPassword(
    @Body('email') email: string,
    @Body('otp') otp: string,
    @Body('newPassword') newPassword: string,
  ): Promise<string> {
    return this.authService.resetPassword(email, otp, newPassword);
  }
}
