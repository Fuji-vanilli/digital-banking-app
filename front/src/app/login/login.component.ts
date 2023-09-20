import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {

  formLogin!: FormGroup

  constructor(private formBuilder: FormBuilder,
              private authService: AuthService,
              private rooter: Router) { }

  ngOnInit(): void {
    this.formLogin= this.formBuilder.group({
      username: ['', Validators.required],
      password: ['', Validators.required]
    })
  }

  handleLogin(){
    console.log(this.formLogin.value);

    let username= this.formLogin.value.username;
    let password= this.formLogin.value.password;

    this.authService.login(username, password).subscribe({
      next: data=> {
        this.authService.loadProfile(data);
        this.rooter.navigateByUrl('/admin');
      },
      error: err=> {
        console.log(err);
      }
    });
  }
}
