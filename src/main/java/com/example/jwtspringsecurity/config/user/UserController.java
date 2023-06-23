package com.example.jwtspringsecurity.config.user;

import com.example.jwtspringsecurity.BaseResponceDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    UserService userService;

    @PostMapping("/api/auth/register")
    public BaseResponceDto registerUser(@RequestBody User newUser){
        if(userService.createUser(newUser)){
            return new BaseResponceDto("success");
        }else {
            return new BaseResponceDto("failed");
        }

    }

    @PostMapping("/api/auth/login")
    public BaseResponceDto loginUser(@RequestBody UserLoginDto loginDetails){
        if(userService.checkUserNameExists(loginDetails.getEmail())){
            if(userService.verifyUser(loginDetails.getEmail(),loginDetails.getPassword())){
                Map<String,Object> data = new HashMap<>();
                data.put("token",userService.generateToke(loginDetails.getEmail(),loginDetails.getPassword()));
                return new BaseResponceDto("success",data);
            }else {
                return new BaseResponceDto("wrong password");
            }
        }else {
            return new BaseResponceDto("user not exist");
        }
    }

    @GetMapping("/api/admin/products")
    public String getProductsAdmin(){
        return "list of products request from admin";
    }

    @GetMapping("/api/seller/products")
    public String getProductsSeller(){
        return "list of products request from seller";
    }

    @GetMapping("/api/products")
    public String getProducts(){
        return "list of products";
    }

}
