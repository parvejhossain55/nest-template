import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly mailerService: MailerService) {}

  async sendWelcomeEmail(to: string, name: string): Promise<void> {
    try {
      await this.mailerService.sendMail({
        to,
        subject: 'Welcome!',
        template: './welcome', // resolves to templates/welcome.hbs
        context: { name },
      });
    } catch (error) {
      this.logger.error(`Failed to send welcome email to ${to}`, error.stack);
      throw error; // let caller decide: retry, queue, alert, etc.
    }
  }
}