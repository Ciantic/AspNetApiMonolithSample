/* tslint:disable */
// This file is generated from the API with command line argument "gensdk".
// Do not edit this file.

import { request } from "./request";

export interface ApiPromise<T> extends PromiseLike<T> {
    onError(errorCode: "ValidationError", cb: (data: { fields : { [k: string]: string[] }, messages : string[] }) => void);
    onError(errorCode: "NotFound", cb: (data: null) => void);
    onError(errorCode: "NotAuthorized", cb: (data: null) => void);
    onError(errorCode: "Forbidden", cb: (data: null) => void);
    onError(errorCode: "UndefinedError", cb: (data: null) => void);
}
export const Api = {
    Account : {
        Register : (body: { email : string, password : string }) =>
            request<ApiPromise<string>>("Account/Register", "POST", body),
        LoggedIn : () =>
            request<ApiPromise<{ id : string, email : string }>>("Account/LoggedIn", "POST", null),
        ChangePassword : (body: { currentPassword : string, newPassword : string }) =>
            request<ApiPromise<string>>("Account/ChangePassword", "POST", body),
        ResetPassword : (body: { email : string, code : string, newPassword : string }) =>
            request<ApiPromise<string>>("Account/ResetPassword", "POST", body),
        ForgotPassword : (body: { email : string }) =>
            request<ApiPromise<string>>("Account/ForgotPassword", "POST", body),
        ConfirmEmail : (body: { email : string, code : string }) =>
            request<ApiPromise<string>>("Account/ConfirmEmail", "POST", body),
        LogoutAllApplications : () =>
            request<ApiPromise<string>>("Account/LogoutAllApplications", "POST", null)
    },
    Frontend : {
        Thingies : {
            GetByName : (body: { name : string }) =>
                request<ApiPromise<{ id : number, name : string }>>("Frontend/Thingies/GetByName", "POST", body),
            GetById : (body: { id : number }) =>
                request<ApiPromise<{ id : number, name : string }>>("Frontend/Thingies/GetById", "POST", body),
            Store : (body: { thingie : { id : number, name : string } }) =>
                request<ApiPromise<{ id : number, name : string }>>("Frontend/Thingies/Store", "POST", body)
        }
    }
};
