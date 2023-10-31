require('dotenv').config();
import http from 'http';
import Server from './bin/server'
import Logger  from './src/V1/helpers/logger';

class Application {
    constructor(){
        this.app = "";
        this.bind = "";
        this.port = "";
        this.server = "";
        this.serverObj = "";
        this.logger = "";
    }

    async initApp(){
        this.port = process.env.PORT;
        this.serverObj = new Server();
        this.app = await this.serverObj.initServer();
        this.logger = new Logger();
        await this.logger.init();
        this.app.set('port',this.port);
        await this.initAppServer();
    }

    async initAppServer(){
        this.server = await http.createServer(this.app);
        this.server.listen(this.port);
        this.address = this.server.address();
        this.bind = typeof this.address === 'string'
        ? `pipe ${this.address}`
        :`port ${this.address.port}`;
        this.logger.logDebug(`Listening On: ${this.bind}`);
        this.logger.logInfo(`Server running on: ${this.port}`);
    }
}

const app = new Application();

(async () => {
    process.setMaxListeners(0);
    await app.initApp();
})();

// The unhandledRejection listener
process.on('unhandledRejection', error => {
	console.error('unhandledRejection', error);
});

