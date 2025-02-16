import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // TODO: verify the token exists and add the user data to the request object
  const authHeader = req.headers.authorization;

  if (authHeader) {
    // Takes the token from the authorization header
    const token = authHeader.split(' ')[1];
    // Takes the secret key from the environment variables
    const secretKey = process.env.JWT_SECRET_KEY || '';
    // Verifies the token
    jwt.verify(token, secretKey, (err, user ) => {
      if (err) {
        return res.sendStatus(403); // Send forbidden status if the token is invalid
      }

      // Attaches the user information to the request object
      req.user = user as JwtPayload;
      // Calls the next middleware function
      return next();
    });
  } else {
    // Sends unauthorized status if no authorization header is present
    res.sendStatus(401);
  }
};
