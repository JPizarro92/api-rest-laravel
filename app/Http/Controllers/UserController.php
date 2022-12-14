<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;

class UserController extends Controller
{
    public function pruebas(Request $request){
        return "Acción pruebas User Controller";
    }

    public function register(Request $request){
        
        $json = $request -> input('json', null);
        $params = json_decode($json);
        $params_array = json_decode($json, true);

        if(!empty($params) && !empty($params_array)){
            //Limpieza de datos
            $params_array = array_map('trim', $params_array);
        
            //Validación de datos
            $validate = \Validator::make($params_array, [
                'name'      => 'required|alpha',
                'surname'   => 'required|alpha',
                'email'     => 'required|email|unique:users',
                'password'  => 'required'
            ]);
        
            if($validate -> fails()){
                $data = array(
                    'status'    => 'error',
                    'code'      => 404,
                    'message'   => 'usuario no creado',
                    'errors'    => $validate->errors()
                );
                return response() -> json($data,400);
            }else{

                //Cifrar password
                $pwd = hash('sha256', $params->password);

                //Creación de usuario
                $user = new User();

                $user-> name     = $params_array['name'];
                $user-> surname  = $params_array['surname'];
                $user-> email    = $params_array['email'];
                $user-> password = $pwd;
                $user-> role     = 'ROLE_USER';

                //Guardar Usuario
                $user->save();

                $data = array(
                    'status'    => 'success',
                    'code'      => 200,
                    'message'   => 'usuario creado',
                    'user'      => $user
                );
            }
        }else{
            $data = array(
                'status'    => 'error',
                'code'      => 404,
                'message'   => 'usuario no creado',
                'errors'    => 'se debe ingresar los datos'
            );
        }

        return response()->json($data, $data['code']);
    }

    public function login(Request $request){
        
        $jwtAuth = new \JwtAuth();
        
        //Recibir los datos por post
        $json = $request->input('json', null);
        $params = json_decode($json);
        $params_array = json_decode($json, true);
        
        $validated = \Validator::make($params_array,[
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if($validated->fails()){
            $signup = array(
                'status' => 'error',
                'code'   => 404,
                'message'=> 'El Usuario no se ha podido identificar.',
                'errors' => $validated->errors()
            );
        }else{
            //Cifrar la contraseña
            $pwd = hash('sha256', $params->password);
            $signup = $jwtAuth->signup($params->email, $pwd);
            
            if(!empty($params->getToken)){
                $signup = $jwtAuth->signup($params->email, $pwd, true);
            }
            
        }
        
        return response()->json($signup,200);
    }

    public function update(Request $request){
        //Comprobar si el usuario está identificado
        $token = $request->header('Authorization');
        $jwtAuth = new \JwtAuth();
        $checkToken = $jwtAuth->checkToken($token);
        
        //Recoger los datos por post
        $json = $request->input('json',null);
        $params_array = json_decode($json, true);
        
        if($checkToken && !empty($params_array)){
            
            //Sacar usuario identificado
            $user = $jwtAuth->checkToken($token, true);

            //Validar datos
            $validate = \Validator::make($params_array,[
                'name' => 'required|alpha',
                'surname' => 'required|alpha',
                'email' => 'required|email|unique:users'.$user->sub
            ]);

            //Quitar los campos que no quiero actualizar
            unset($params_array['id']);
            unset($params_array['role']);
            unset($params_array['password']);
            unset($params_array['created_at']);
            unset($params_array['remember_token']);

            //Actualizar usuario
            $user_update = User::where('id', $user->sub)->update($params_array);

            //Devolver array con resultado
            $data = array(
                'code'      => 200,
                'status'    => 'success',
                'message'   => $user,
                'change'    => $params_array
            );
        }else{
            $data = array(
                'code'      => 400,
                'status'    => 'error',
                'message'   => 'El usuario no se encuentra identificado.'
            );
        }
        return response()->json($data, $data['code']);
    }

}
