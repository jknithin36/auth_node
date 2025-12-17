import { connectDatabase } from "./config/databse";
import dotenv from "dotenv";

import http from "http";
import app from "./app";
//
dotenv.config();
//
async function startServer() {
  await connectDatabase();

  const server = http.createServer(app);

  server.listen(process.env.PORT, () => {
    console.log(`Server is Listening on Port :${process.env.PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Error while starting the server", err);
  process.exit(1);
});
