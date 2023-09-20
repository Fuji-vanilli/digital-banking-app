import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Router, UrlSegment } from '@angular/router';
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

  constructor(private httpClient: HttpClient,
              private router: Router) { }

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

    window.localStorage.setItem("jwt", this.accessToken);
  }

  logout(){
    this.isAuthenticated= false;
    this.accessToken= undefined;
    this.username= undefined;
    this.roles= undefined;

    window.localStorage.removeItem("jwt");

    this.router.navigate(['/login']);
  }

  loadJwtFromLocalStorage() {
    let token= window.localStorage.getItem('jwt');

    if(token){
      this.loadProfile({'access-token': token});
      this.router.navigate(['/admin/customers']);
    }
  }
}
