<?php

use Illuminate\Http\Request;

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});



Route::group(['middleware' => ['jwt.auth','api']], function () {
  
    // all routes to protected resources are registered here  
    Route::get('users/list', function(){
        $users = App\User::all();
        
        $response = [ 'success' => true, 'data' => $users];
        return response()->json($response, 201);
    });

    // Logged out
    Route::get('/user/logout', 'UserController@logout');
});

Route::group(['middleware' => 'api'], function () {
  
    // The registration and login requests doesn't come with tokens 
    // as users at that point have not been authenticated yet
    // Therefore the jwtMiddleware will be exclusive of them

    Route::post('user/login', 'UserController@login');
    Route::post('user/register', 'UserController@register');
    
});