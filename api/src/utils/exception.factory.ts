import { ValidationError } from '@nestjs/common'
import { InvalidBodyException } from './exceptions/invalid-body.exception'

const getMessages = (errors: ValidationError[]) => {
  const messages = [];

  for (const error of errors) {
    if (error.constraints) {
      messages.push(...Object.values(error.constraints));
    }
    if (error.children.length !== 0) {
      messages.push(getMessages(error.children))
    }
  }

  return messages;
}

export const validationExceptionFactory = () => (errors: ValidationError[]) => {
  return new InvalidBodyException(getMessages(errors));
}