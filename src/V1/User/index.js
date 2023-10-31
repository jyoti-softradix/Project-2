import userController from './user.controller';
import schemaValidator from '../helpers/schemaValidator';
import { createUser, serProfileValidator, listAllUser, resendInvite } from './user.validator';
import { getAccessRoles } from '../helpers/commonFunction';
import Authorization from '../helpers/authorization';
export default class User {
    constructor(router, db) {
        this.authorization = new Authorization();
        this.router = router;
        this.db = db;
        this.userInstance = new userController()
    }
    async routes() {
        await this.userInstance.init(this.db)
        await this.authorization.init(this.db);

        let userAccess = await getAccessRoles(this.db);

        /** invite users */
        this.router.post('/user/invite', await this.authorization.authorize([userAccess.Admin]), schemaValidator(createUser), (req, res) => {
            this.userInstance.inviteUser(req, res)
        });

        /** set-profile */
        this.router.post('/user/set-profile', schemaValidator(serProfileValidator), (req, res) => {
            this.userInstance.serProfile(req, res)
        });

        /** list all users */
        this.router.get('/users/list', await this.authorization.authorize([userAccess.Admin]), schemaValidator(listAllUser), (req, res) => {
            this.userInstance.listUser(req, res)
        });

        /** list of all pending users */
        this.router.get('/users/pending/list', await this.authorization.authorize([userAccess.Admin]), (req, res) => {
            this.userInstance.getAllPendingUser(req, res)
        });

        /** delete users */
        this.router.delete('/user/delete', await this.authorization.authorize([userAccess.Admin]), (req, res) => {
            this.userInstance.deleteUser(req, res)
        });

        /** resend invite */
        this.router.post('/user/resend-invite', await this.authorization.authorize([userAccess.Admin]), schemaValidator(resendInvite), (req, res) => {
            this.userInstance.resendInvite(req, res)
        });
    }
}


