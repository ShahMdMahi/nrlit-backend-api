import express, { Express, Request, Response, NextFunction } from "express";
import { env } from "./libs/env.js";

const app: Express = express();
const PORT = env.PORT;
const NODE_ENV = env.NODE_ENV;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req: Request, res: Response) => {
  res.send("Hello, World!");
});

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

app.listen(PORT, () => {
  console.log(
    `Server is running at http://localhost:${PORT} in ${NODE_ENV} mode.`
  );
});
