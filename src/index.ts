import { bootstrapWebApp } from './web/nestjs/main';

bootstrapWebApp()
    .then(async app => {
        await app.listen(process.env.PORT ?? 5000);
    })
    .catch(console.error);
