<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Exceptions;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class UserController extends Controller
{
    public function store(Request $request)
    {
        // Validate the request data
        $request->validate([
            'name' => 'required|string|unique:users',
            'phone' => 'required|string|unique:users',
            'password' => 'required|string|min:8',
            'ispharmacy' => 'sometimes|boolean',
            'iswarehouse' => 'sometimes|boolean',
        ]);
    
        $request->merge(['password' => Hash::make($request->password)]);
    
        if ($request->has('ispharmacy')) {
            $request->merge(['iswarehouse' => !$request->input('ispharmacy')]);
        } elseif ($request->has('iswarehouse')) {
            $request->merge(['ispharmacy' => !$request->input('iswarehouse')]);
        }
    
        // Generate a new token for the user
        $token = Str::random(60);
        $request->merge(['api_token' => $token]);
    
        $user = User::create($request->all());
    
        return response()->json([
            'message' => 'User created successfully',
            'user' => $user,
            'token' => $token
        ], 201);
    }





    public function login(Request $request)
    {
        $phone = $request->input('phone');
        $password = $request->input('password');
    
        // Find the user by phone
        $user = User::where('phone', $phone)->first();
    
        // If user doesn't exist or password is incorrect
        if (!$user || !Hash::check($password, $user->password)) {
            return response()->json([
                'Error' => 'Phone number does not exist or the Password is incorrect'
            ], 401);
        }
    
        // If phone and password are correct
        $token = Str::random(60);
    
        // Store the token in the database
        $user->api_token = $token;
        $user->save();
    
        return response()->json([
            'message' => 'User logged in successfully',
            'token' => $token
        ], 200);
    }
    


    public function logout(Request $request)
    {
        $phone = $request->input('phone');
        $user = User::where('phone', $phone)->first();
    
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }
    
        // Invalidate the token
        $user->api_token = null;
        $user->save();
    
        return response()->json(['message' => 'User logged out successfully'], 200);
    }


public function getUser(Request $request)
{
    // Get the token from the request header
    $token = $request->header('Authorization');

    // Find the user by the token
    $user = User::where('api_token', $token)->first();

    // If the user doesn't exist
    if (!$user) {
        return response()->json([
            'Error' => 'Invalid token'
        ], 401);
    }

    // If the user exists
    return response()->json([
        'message' => 'User found',
        'user' => $user
    ], 200);
}


}
