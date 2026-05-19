import http from 'node:http';
import { loadConfig } from './config.mjs';
import { createApp } from './app.mjs';

export async function startServer(overrides = {}) {
  const config = { ...loadConfig(), ...overrides };
  const app = await createApp(config);
  const server = http.createServer(app.handler);

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });

  return {
    server,
    config,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
      app.close();
    }
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer()
    .then(({ config }) => {
      console.log(`Ploinky Wormhole server listening on http://${config.host}:${config.port}`);
    })
    .catch((error) => {
      console.error(error.message || String(error));
      process.exit(1);
    });
}
