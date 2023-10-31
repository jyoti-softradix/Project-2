import Auth from "./Auth/index";
import User from "./User/index";


export default class Routes {
  constructor(router, db) {
    this.router = router;
    this.DatabaseConnect = db;
  }

  async routesRegistration() {
    this.db = await this.DatabaseConnect.getDB();

    this.auth = new Auth(this.router, this.db);
    await this.auth.routes();

    this.user = new User(this.router, this.db);
    await this.user.routes();

    
  }
}
