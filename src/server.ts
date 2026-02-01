import "dotenv/config"; import app from "./app.js";
const port=Number(process.env.PORT??4010); app.listen(port,()=>console.log(`SecureShift API listening on :${port}`));
