import { NestFactory } from '@nestjs/core';

import { AppModule } from './app.module';

interface WebApp {
    listen: (port: number | string) => Promise<void>;
}

async function bootstrapWebApp(): Promise<WebApp> {
    const app = await NestFactory.create(AppModule);

    return app;
}

export { bootstrapWebApp };
