export interface User {
  id: string;
  email: string;
  firstName: string;
  username?: string;
  lastName: string;
  isVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}