import authController from "./auth.controller"
import schemaValidator from "../helpers/schemaValidator"
import { loginValidator, forgotPasswordValidator, resetPasswordValidator, changePasswordValidator, updateInfoValidator } from "./auth.validator"
import Authorization from "../helpers/authorization";
import { getAccessRoles } from '../helpers/commonFunction';

export default class auth {
    constructor(router, db) {
        this.authorization = new Authorization();
        this.router = router;
        this.db = db;
        this.authInstance = new authController();
    }
    async routes() {
        await this.authInstance.init(this.db);
        await this.authorization.init(this.db);
        let userAccess = await getAccessRoles(this.db);

        /** user signup */
        this.router.post('/auth/signup', schemaValidator(loginValidator), (req, res) => {
            this.authInstance.signup(req, res)
        })

        /** user login */
        this.router.post('/auth/login', schemaValidator(loginValidator), (req, res) => {
            this.authInstance.login(req, res)
        })

        /** forgot password */
        this.router.post('/auth/forgot-password', schemaValidator(forgotPasswordValidator), (req, res) => {
            this.authInstance.forgotPassword(req, res)
        })

        /** reset password */
        this.router.post('/auth/reset-password', schemaValidator(resetPasswordValidator), (req, res) => {
            this.authInstance.resetPassword(req, res)
        })

        /* change password */
        this.router
            .route("/auth/change-password")
            .post(
                await this.authorization.authorize([userAccess.Admin, userAccess.SalesRepresentative]),
                schemaValidator(changePasswordValidator),
                (req, res) => this.authInstance.changePassword(req, res),
            );

        /* My account information */
        this.router.route("/auth/my-account-information")
            .get(
                await this.authorization.authorize([userAccess.Admin, userAccess.SalesRepresentative]),
                (req, res) => this.authInstance.getProfile(req, res),
            );

        /* update account information */
        this.router.route("/auth/update-account-information").post(
            await this.authorization.authorize([userAccess.Admin, userAccess.SalesRepresentative]),
            schemaValidator(updateInfoValidator),
            (req, res) => this.authInstance.updateProfile(req, res),
        );

        /* verify token */
        this.router.route("/token-verify").post((req, res) => this.authInstance.verifyToken(req, res));
    }
}

