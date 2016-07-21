/* tslint:disable */
// Do not edit this file.
// This file is generated from the API with command line argument "gensdk".

// About this-keyword and <T> in it see: https://github.com/Microsoft/TypeScript/issues/6452

import { request } from "./request";

export interface ApiErrors {
    onError<T>(this: T, errorCode: "ValidationError", cb: (data: { fields : { [k: string]: { code : string, message : string, data : {  } }[] }, general : { code : string, message : string, data : {  } }[] }) => void): T;
    onError<T>(this: T, errorCode: "NotFound", cb: (data: null) => void): T;
    onError<T>(this: T, errorCode: "NotAuthorized", cb: (data: null) => void): T;
    onError<T>(this: T, errorCode: "Forbidden", cb: (data: null) => void): T;
    onError<T>(this: T, errorCode: "UndefinedError", cb: (data: null) => void): T;
}
export const Api = {
    Account : {
        Register : (body: { email : string, password : string }) =>
            request<string>("Account/Register", "POST", body),
        LoggedIn : () =>
            request<{ id : string, email : string }>("Account/LoggedIn", "POST", null),
        ChangePassword : (body: { currentPassword : string, newPassword : string }) =>
            request<string>("Account/ChangePassword", "POST", body),
        ResetPassword : (body: { email : string, code : string, newPassword : string }) =>
            request<string>("Account/ResetPassword", "POST", body),
        ForgotPassword : (body: { email : string }) =>
            request<string>("Account/ForgotPassword", "POST", body),
        ConfirmEmail : (body: { email : string, code : string }) =>
            request<string>("Account/ConfirmEmail", "POST", body),
        LogoutAllApplications : () =>
            request<string>("Account/LogoutAllApplications", "POST", null)
    },
    Frontend : {
        Thingies : {
            GetByName : (body: { name : string }) =>
                request<{ id : number, name : string }>("Frontend/Thingies/GetByName", "POST", body),
            GetById : (body: { id : number }) =>
                request<{ id : number, name : string }>("Frontend/Thingies/GetById", "POST", body),
            Store : (body: { thingie : { id : number, name : string } }) =>
                request<{ id : number, name : string }>("Frontend/Thingies/Store", "POST", body)
        }
    }
};
