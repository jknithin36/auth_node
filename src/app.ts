import express from "express";
import cookieParser from "cookie-parser";
import authRouter from "./routes/auth.routes";
import userRouter from "./routes/user.routes";
import adminRouter from "./routes/admin.routes";
const app = express();

app.use(express.json()); // parse the json that is coming from frontend

app.use(cookieParser()); // parse cokkies in to request.cokkies

app.get("/health", (req, res) => {
  res.json({ status: "OK" });
});

app.use("/auth", authRouter);
app.use("/user", userRouter);
app.use("/admin", adminRouter);

export default app;
