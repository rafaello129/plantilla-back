
import { Request, Response } from 'express';
import { CustomError } from '../../domain/errors';
import { LoginDto, RegisterDto } from '../../domain/dtos/auth';
import { AuthRepository } from '../../domain/repositories';
import { Renew } from '../../domain/use-cases/auth/renew.use-case';
import { RegisterUser } from '../../domain/use-cases/auth/register.use-case';
import { LoginUser } from '../../domain/use-cases/auth';

export class AuthController {

    constructor( 
        private readonly authRepository: AuthRepository,
    ) 
    {}

    private handleError = ( error: unknown, res: Response ) => {
        if ( error instanceof CustomError ) {
            return res.status(error.statusCode).json({ error, message: error.message, status: false })
        }

        return res.status(500).json({
            error: 'Internal Server Error'
        })
    }


    login = (req: Request, res: Response) => {
        const { role } = req.params;
        const [error, loginUserDto] = LoginDto.create({ ...req.body, role });
        if (error) return res.status(400).json({ error });
        new LoginUser(this.authRepository)
            .execute(loginUserDto!)
            .then(data => res.json(data))
            .catch(error => this.handleError(error, res));
    }

    register = ( req: Request, res: Response ) => {
        const { role } = req.params;
        const [error, registerDto] = RegisterDto.create({...req.body, role });
        if ( error ) return res.status(400).json({ error });
        new RegisterUser(this.authRepository)
          .execute( registerDto! )
          .then( data => res.json(data) )
          .catch( error => this.handleError(error, res) );
    }


    renew = ( req: Request, res: Response ) => {
        new Renew()
            .execute({ ...req.body.user } )
            .then( data =>{return res.json(data)} )
            .catch( error => this.handleError(error, res) );
    }


}