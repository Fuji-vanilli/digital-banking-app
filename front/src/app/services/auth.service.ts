import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { UrlSegment } from '@angular/router';
import jwtDecode from 'jwt-decode';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  url= "http://localhost:8085";

  isAuthenticated= false;
  accessToken: any;
  username: any;
  roles: any;

  constructor(private httpClient: HttpClient) { }

  public login(username: string, password: string) {
    let options= {
      headers: new HttpHeaders().set("Content-Type", "application/x-www-form-urlencoded")
    }
    let params= new HttpParams().set("username", username).set("password", password);
    return this.httpClient.post(this.url+"/auth/login", params, options);
  }
  loadProfile(data: any) {
    this.isAuthenticated= true;
    this.accessToken= data['access-token'];

    let decodeJwt: any= jwtDecode(this.accessToken);

    this.username= decodeJwt.sub;
    this.roles= decodeJwt.scope;
  }
}
