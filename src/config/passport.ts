import { Request, Response, NextFunction } from "express";
import passport from "passport";
import { Strategy as JWTStrategy, ExtractJwt } from "passport-jwt";
import jwt from "jsonwebtoken";
import { User } from '../models/User'
import dotenv from 'dotenv';

dotenv.config();

const notAuthorizedJson = { status: 401, message: 'Não autorizado' };
const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET as string
}

passport.use(new JWTStrategy(options, async (payload, done) => {
    const user = await User.findByPk(payload.id);
    return user ? done(null, user) : done(notAuthorizedJson, false)

}));

export const generateToken = (data: object) => {
   return jwt.sign(data, process.env.JWT_SECRET as string, {expiresIn: '1h'});
}

export const privateRoute = (req: Request, res: Response, next: NextFunction) => {
    const authFunction = passport.authenticate('jwt', (err, user) => {

        return user ? next() : next(notAuthorizedJson)
    });
    authFunction(req, res, next);
}

export default passport;