declare namespace Express {
  interface Request {
    id: string;
    useragent: useragent.UserAgentInfo;
  }
}
