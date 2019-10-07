<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use JWTAuth;
use JWTAuthException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{

    private function getToken($email, $password)
    {
        $token = null;
        //$credentials = $request->only('email', 'password');
        try {
            if (!$token = JWTAuth::attempt( ['email' => $email, 'password' => $password])) {
                return response()->json([
                    'response' => 'error',
                    'message' => 'Password or email is invalid',
                    'token'=> $token
                ]);
            }
        } catch (JWTAuthException $e) {
            return response()->json([
                'response' => 'error',
                'message' => 'Token creation failed',
            ]);
        }
        return $token;
    }

    public function login(Request $request)
    {
        $user = User::where(DB::raw("BINARY `username`"), $request->user_or_email)->orWhere(DB::raw("BINARY `email`"), $request->user_or_email)->first();

        if ($user && Hash::check($request->password, $user->password)){
            // The passwords matched
            $token = self::getToken($request->user_or_email, $request->password);
            $user->auth_token = $token;
            $user->save();
            $response = ['success' => true, 'data' => [ 'id'=>$user->id, 'auth_token' => $user->auth_token, 'username' => $user->username, 'email' => $user->email]];           
        }
        else{
            $response = ['success' => false, 'data' => 'Record doesnt exists'];
        }
        
        return response()->json($response, 201);
    }

    public function register(Request $request)
    { 
        $payload = [
            'password' => Hash::make($request->password),
            'email' => $request->email,
            'username' => $request->username,
            'auth_token' => ''
        ];
                  
        $user = new \App\User($payload);

        if ($user->save())
        {
            $token = self::getToken($request->email, $request->password); // generate user token
            
            if (!is_string($token))  return response()->json(['success' => false,'data' => 'Token generation failed'], 201);
            
            $user = User::where('email', $request->email)->get()->first();
            
            $user->auth_token = $token; // update user token
            
            $user->save();
            
            $response = ['success' => true, 'data' => ['username'=>$user->username, 'id' => $user->id, 'email' => $request->email, 'auth_token' => $token]];        
        }
        else{

            $response = ['success' => false, 'data' => 'Couldnt register user'];

        }
        
        return response()->json($response, 201);
    }

    public function logout()
    {
        // Destroy token
        JWTAuth::invalidate(JWTAuth::getToken());

        $response = ['success' => true, 'data' => 'Logged out successfully'];

        return response()->json($response, 201);
    }
}