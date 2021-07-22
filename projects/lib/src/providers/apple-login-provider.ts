import { BaseLoginProvider } from '../entities/base-login-provider';
import { SocialUser } from '../entities/social-user';

export type AppleOptions = {
  redirectURI?: string,
  scope?: string,
  response_mode?: string
};

interface AppleSignInResponse {
  authorization: AppleAuthorization,
  user: AppleUser,
  error: any,
}

interface AppleUser {
  name: { firstName: string; lastName: string };
  email: string;
}

interface AppleAuthorization {
  state: string,
  code: string,
  id_token: string
}

declare let AppleID: any;

export class AppleLoginProvider extends BaseLoginProvider {
  public static readonly PROVIDER_ID: string = 'APPLE';

  private initOptions: AppleOptions = {
    scope: 'name email',
    response_mode: 'form_post',
  };

  constructor(private clientId: string, initOptions?: AppleOptions) {
    super();

    this.initOptions = {
      ...this.initOptions,
      ...initOptions,
    };
  }

  initialize(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.loadScript(
          AppleLoginProvider.PROVIDER_ID,
          'https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js',
          () => {
            try {
              AppleID.auth.init({
                clientId: this.clientId,
                scope: this.initOptions,
                redirectURI: this.initOptions.redirectURI ?? location.origin,
                state: '',
                nonce: '',
                usePopup: true,
              });

              resolve();
            } catch (e) {
              reject(e);
            }
          }
        );
      } catch (err) {
        reject(err);
      }
    });
  }

  getLoginStatus(): Promise<SocialUser> {
    return new Promise((resolve, reject) => {
      const auth = this.retrieveAuth();

      if (auth) {
        const user = this.getUser(auth.authorization, auth.user);
        if (!user) {
          reject(
            `No user is currently logged in with ${AppleLoginProvider.PROVIDER_ID}`
          );
        } else {
          resolve(user);
        }
      } else {
        reject(
          `No user is currently logged in with ${AppleLoginProvider.PROVIDER_ID}`
        );
      }
    });
  }

  signIn(): Promise<SocialUser> {
    return new Promise((resolve, reject) => {
      AppleID.auth
        .signIn(this.initOptions)
        .then((response: AppleSignInResponse) => {
          if (response.error) {
            reject(response.error);
          } else {
            const user: SocialUser = this.getUser(
              response.authorization,
              response.user
            );
            user.response = response;

            this.persistAuth(response.authorization, response.user);

            resolve(user);
          }
        });
    });
  }

  signOut(revoke?: boolean): Promise<void> {
    return new Promise((resolve, reject) => {
      this.clearAuth();
      resolve();
    });
  }

  private getUser(auth: AppleAuthorization, user: AppleUser): SocialUser {
    if (!auth || !user) {
      return undefined;
    }

    const socialUser: SocialUser = new SocialUser();

    socialUser.provider = AppleLoginProvider.PROVIDER_ID;
    socialUser.id = auth.id_token;
    socialUser.authToken = auth.id_token;
    socialUser.name = `${user.name.firstName} ${user.name.lastName}`;
    socialUser.email = user.email;
    socialUser.idToken = auth.id_token;
    socialUser.firstName = user.name.firstName;
    socialUser.lastName = user.name.lastName;

    return socialUser;
  }

  private persistAuth(auth: AppleAuthorization, user: AppleUser): void {
    const item = JSON.stringify({ authorization: auth, user: user });
    localStorage.setItem(`${AppleLoginProvider.PROVIDER_ID}_auth`, item);
  }

  private retrieveAuth(): {
    authorization: AppleAuthorization;
    user: AppleUser;
  } {
    const item = localStorage.getItem(`${AppleLoginProvider.PROVIDER_ID}_auth`);
    return item && item.length > 0 ? JSON.parse(item) : undefined;
  }

  private clearAuth(): void {
    localStorage.removeItem(`${AppleLoginProvider.PROVIDER_ID}_auth`);
  }
}
