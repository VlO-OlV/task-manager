import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { EmailData } from './dtos/email-data.dto';

@Injectable()
export class EmailService {

  constructor (
    private mailerService: MailerService,
  ) {}

  async sendEmail (options: EmailData) {
    await this.mailerService.sendMail({
      to: options.to,
      subject: options.subject,
      text: options.message,
    });
  }
}