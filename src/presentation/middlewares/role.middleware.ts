import { Request, Response, NextFunction } from "express";
import { UserEntity } from "../../domain/entities";

export class RoleMiddleware {
  static isAdmin = (req: Request, res: Response, next: NextFunction) => {
    const user: UserEntity = req.body.user;

    if (!user) {
        return res.status(500).json({ error: 'Internal server error: user not found in request' });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Administrator access required' });
    }
    
    next();
  };
}