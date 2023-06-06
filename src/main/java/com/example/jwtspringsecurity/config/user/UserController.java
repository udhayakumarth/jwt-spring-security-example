package com.example.jwtspringsecurity.config.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    @Autowired
    UserService userService;

    @PostMapping("/api/auth/register")
    public String registerUser(@RequestBody User newUser){
        if(userService.createUser(newUser)){
            return "User Registered";
        }else {
            return "Try again";
        }

    }

    @PostMapping("/api/auth/login")
    public String loginUser(@RequestBody UserLoginDto loginDetails){
        if(userService.checkUserNameExists(loginDetails.getEmail())){
            if(userService.verifyUser(loginDetails.getEmail(),loginDetails.getPassword())){
                return userService.generateToke(loginDetails.getEmail(),loginDetails.getPassword());
            }else {
                return "Password Invalid";
            }
        }else {
            return "User Not exist";
        }
    }

    @GetMapping("/api/products")
    public String getProducts(){
        return "list of products";
    }
}
