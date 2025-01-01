// src/types/User.ts
export interface User {
    id: string;
    email: string;
    password: string; // Consider storing a hashed version
}