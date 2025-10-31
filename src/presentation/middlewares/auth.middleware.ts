import { Request, Response, NextFunction } from "express";
import { JwtAdapter } from "../../config";
import { PostgresDatabase } from "../../data/postgres";
import { User } from "../../data/postgres/entities";
import { QueryRunner } from "typeorm";

export class AuthMiddleware {
  static validateJwt = async (req: Request, res: Response, next: NextFunction) => {
    const authorization = req.headers['authorization'];
    if (!authorization || !authorization.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Invalid or missing accessToken' });
    }

    const accessToken = authorization.split(' ')[1];
    const queryRunner: QueryRunner = PostgresDatabase.dataSource.createQueryRunner();

    try {
      await queryRunner.connect();
      const payload = await JwtAdapter.validateToken<{ uid: string }>(accessToken);

      if (!payload) {
        return res.status(401).json({ error: 'Invalid accessToken' });
      }


      const user = await queryRunner.manager.findOne(User, {
        where: { uid: payload.uid, is_active: true },
        select: [
          'uid', 'username', 'email', 'phone', 'password', 'is_active',
          'is_online', 'is_disabled', 'is_google', 'created_at',
          'updated_at', 'picture', 'role'
        ]
      });

      if (!user || !user.is_active || user.is_disabled) {
        return res.status(401).json({
          error: user ? (user.is_disabled ? 'User disabled' : 'User inactive') : 'Invalid accessToken'
        });
      }

      delete user.password;
      if(!req.body) {
        req.body = {};
      }
      req.body.user = { ...user };

      next();
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      await queryRunner.release();
    }
  };

}
