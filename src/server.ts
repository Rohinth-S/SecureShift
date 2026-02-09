import "dotenv/config";
import app from "./app.js";
import { bootstrapPersistence, persistenceMode } from "./persistence.js";

const port = Number(process.env.PORT ?? 4010);
bootstrapPersistence("secureshift")
  .then((result) => {
    app.listen(port, () =>
      console.log(
        `SecureShift API listening on :${port} (${result.mode}/${persistenceMode()})`,
      ),
    );
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
