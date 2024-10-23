import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entities/user.entity';
import { Repository } from 'typeorm';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UUID } from 'crypto';
import { MailerService } from '@nestjs-modules/mailer';
import { v4 as uuidv4 } from 'uuid';
// import { v4 as uuidv4 } from '../../src/templates/otp';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService,

    private mailerService: MailerService,
  ) {}

  async resgister(registerUserDto: RegisterUserDto): Promise<User> {
    const hasPassword = await this.hasPassword(registerUserDto.password);
    return await this.userRepository.save({
      ...registerUserDto,
      refreshToken: ' ',
      password: hasPassword,
    });
  }

  async login(loginUserDto: LoginUserDto): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { email: loginUserDto.email },
    });
    if (!user) {
      throw new HttpException('Email not found', HttpStatus.UNAUTHORIZED);
    }
    const checkPass = bcrypt.compareSync(loginUserDto.password, user.password);
    if (!checkPass) {
      throw new HttpException('Password incorrect', HttpStatus.UNAUTHORIZED);
    }
    const payload = { id: user.id, email: user.email, role: user.role };
    return this.generateToken(payload);
  }
  async refreshToken(refreshToken: string): Promise<any> {
    try {
      const verify = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get<string>('SECRET'),
      });
      const checkExistToken = await this.userRepository.findOneBy({
        email: verify.email,
        refreshToken,
      });
      if (checkExistToken) {
        const newPayload = {
          id: verify.id,
          email: verify.email,
          role: verify.role,
        };
        return this.generateToken(newPayload);
      } else {
        throw new HttpException(
          'Refresh token expired',
          HttpStatus.UNAUTHORIZED,
        );
      }
    } catch (error) {
      throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
    }
  }
  private async generateToken(payload: {
    id: string;
    email: string;
    role: string;
  }) {
    const access_token = await this.jwtService.signAsync(payload);
    const refreshToken = await this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('SECRET'),
      expiresIn: this.configService.get<string>('EXP_IN_REFRESH_TOKEN'),
    });
    await this.userRepository.update(
      {
        email: payload.email,
        role: payload.role,
      },
      { refreshToken: refreshToken },
    );
    return { access_token, refreshToken };
  }

  // ==================================================================
  // API gửi mã OTP về email
  async sendOtp(email: string): Promise<string> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new HttpException('Email not found', HttpStatus.NOT_FOUND);
    }

    // Tạo mã OTP.
    const otp = uuidv4().substring(0, 6); // Lấy 6 ký tự đầu tiên
    user.resetPasswordToken = otp;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // OTP có hiệu lực trong 1 giờ
    await this.userRepository.save(user);

    // Gửi email chứa mã OTP.
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Your OTP Code',
      template: '../../src/templates/otp', // Template email

      context: {
        email: user.email,
        name: user.lastName,
        otp, // Truyền OTP vào context
      },
    });

    return 'OTP has been sent to your email';
  }

  // API xác nhận mã OTP
  async verifyOtp(email: string, otp: string): Promise<string> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user || user.resetPasswordToken !== otp) {
      throw new HttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
    }

    if (user.resetPasswordExpires < new Date()) {
      throw new HttpException('OTP has expired', HttpStatus.BAD_REQUEST);
    }

    return 'OTP201';
  }

  // API đặt lại mật khẩu sau khi xác nhận OTP
  async resetPassword(
    email: string,
    otp: string,
    newPassword: string,
  ): Promise<string> {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user || user.resetPasswordToken !== otp) {
      throw new HttpException('Invalid OTP', HttpStatus.BAD_REQUEST);
    }

    if (user.resetPasswordExpires < new Date()) {
      throw new HttpException('OTP has expired', HttpStatus.BAD_REQUEST);
    }

    // Mã OTP hợp lệ, cho phép đổi mật khẩu
    user.password = await this.hasPassword(newPassword);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await this.userRepository.save(user);

    // await this.mailerService.sendMail({
    //   to: user.email,
    //   subject: 'Successfull Password',
    //   template: '../../src/templates/successfullPassword', // Template email.

    //   context: {
    //     email: user.email,
    //     name: user.lastName,
    //   },
    // });
    return 'Password001';
  }
  // =================================================================
  private async hasPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
  }
}
