import { Request } from "express";
import * as useragent from "express-useragent";

export const useragentMiddleware = useragent.express();

export const isMobileUser = (req: Request) => req.useragent?.isMobile;
