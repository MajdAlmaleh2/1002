<?php

use App\Http\Controllers\PharmaceuticalController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;



/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('users', [UserController::class, 'store']);
Route::post('login', [UserController::class, 'login']);
Route::delete('logout',[UserController::class, 'logout']);
Route::get('user', [UserController::class, 'getUser']);

Route::post('pharma',[PharmaceuticalController::class,'store']);