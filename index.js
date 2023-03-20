'use strict'
    const config = require('./config');
    const express = require('express');
    const logger = require('morgan');
    const cors = require('cors');
    const mongojs = require('mongojs');
    const moment = require('moment');
   
    const port = config.PORT;
    const urlDB = config.DB;
    const accesToken = config.TOKEN;

    const db = mongojs(urlDB);
    const id = mongojs.ObjectID;
    const app = express();

    var https = require('https');
    var fs = require('fs');
    var helmet = require('helmet');

    const tokenHelper = require('./helpers/token.helper');
    const PassHelper = require('./helpers/pass.helper');
const { hash } = require('bcrypt');

    var allowCrossTokenMethods = (req,res,next) => {
        res.header("Access-Control-Allow-Methods","*");
        return next();
    }
    
    var allowCrossTokenOrigin = (req,res,next) => {
        res.header("Access-Control-Allow-Origin","*");
        return next();
    }
    
    var allowCrossTokenHeader = (req,res,next) => {
        res.header("Access-Control-Allow-Header","*");
        return next();
    }

    var auth = (req,res,next)=>{
        const queToken = req.headers.token;

        if(queToken === accesToken){
            return next();
        }else{
            return next(new Error("no autorizado"));
        };
    };

    app.use(helmet());
    app.use(logger('dev'));
    app.use(express.urlencoded({extended:false}));
    app.use(express.json());
    app.use(cors());
    app.use(allowCrossTokenHeader);
    app.use(allowCrossTokenMethods);
    app.use(allowCrossTokenOrigin);

    app.get('/api/user', (req, res, next) => {
        
        db.user.find((err, coleccion) => {
            if (err) return next(err);
            res.json('Usuarios del sistema: ')
            res.json(coleccion);
        });
    });
    
    app.get('/api/user/:id', (req, res, next) => {
        
        db.user.findOne({_id: id(req.params.id)}, (err, elemento) => {
            if (err) return next(err);
            res.json(elemento);
        });
     });

    app.post('/api/user',auth, (req, res, next) => {

        const elemento = req.body;

        db.user.save(elemento, (err, coleccionGuardada) => {
            if(err) return next(err);
                    res.json(coleccionGuardada);
            });
    });

    app.put('/api/user/:id',auth, (req, res, next) => {
        
        let elementoId = req.params.id;
        let elementoNuevo = req.body;
        
        db.user.update(
            {_id: id(elementoId)},
            {$set: elementoNuevo}, 
            {safe: true, multi: false}, 
            (err, elementoModif) => {
                if (err) return next(err);
                res.json(elementoModif);
        });

    });
    
    app.delete('/api/user/:id', auth,(req, res, next) => {
        
        let elementoId = req.params.id;
        
        db.user.remove({_id: id(elementoId)}, (err, resultado) => {
            
            if (err) return next(err);
            res.json(resultado);
            
        });
    });

    //metodo signUp()
    app.post('/api/auth', (req, res, next) => {
        
        //1. Recibimos el usuario en el body de la peticion
        const usuario = req.body;
        //2. Verficamos que los datos de usuario esten completos
        if(!usuario.name || !usuario.email || !usuario.password){
            //2.1 Si no estan completos devolvemos un mensaje de error 400
            res.status(400).json({
                error:'Datos faltantes',
                description:'Requiere name, email y password'
            });
        //3. Si los datos estan completos buscamos en la BBDD otro user similar
        }else{
            //3.1 find devuelve un array de documentos con el mismo valor
            // en displayName
            db.user.find({displayName: usuario.name},(err,result)=>{
                if (err) return next(err);
                //3.2 Si el array es vacio de tamaño 0
                if(result.length===0){            
                //3.3 Se encripta la contraseña y se crea una promesa para el hash
                    PassHelper.encriptaPassword(usuario.password).then(hash=>{
                        //3.3.1 Si la promesa se resuelve con un hash se carga el JSON
                        const newUser = {
                            email: usuario.email,
                            displayName: usuario.name,
                            password: hash,
                            signupDate: moment().unix(),
                            lastLogin: moment().unix() 
                        };
                        //4. Se almacena el JSON cargado con el user
                        db.user.save(newUser,(err,result)=>{
                            if(err) return next(err);
                            //4.1 se crea un token con el result del Callback de la
                            // funcion save(elemento,(error,result) => crea token)
                            const newToken = tokenHelper.creaToken(result);
                            //4.2 Devolver al cliente el estado de la operacion
                            res.json({"result":"OK","token":newToken,newUser});
                        });
                    });
                }
                else{
                    res.json('Usuario ya registrado con anterioridad');
                }
            });
        }
    });

    //metodo signIn()
    app.post('/api/auth/reg', (req, res, next) => {
        
        //1. Recibimos el usuario en el body de la peticion
        const usuario = req.body;
        //2. Verficamos que los datos de usuario esten completos
        if(!usuario.email || !usuario.password){
            //2.1 Si no estan completos devolvemos un mensaje de error 400
            res.status(400).json({
                error:'Datos faltantes',
                description:'Requiere email y password'
            });
        //3. Si los datos estan completos buscamos en la BBDD otro user similar
        }else{
            //3.1 find devuelve un array de documentos con el mismo valor
            // en displayName
            db.user.find({email: usuario.email},(err,result)=>{
                if (err) return next(err);
                //3.2 Si el array es vacio de tamaño 0
                if(result.length===0){            
                            res.json('Usuario no registrado');
                }
                else{
                    PassHelper.comparaPassword('ABC',usuario.password).then(passValid=>{
                        if(passValid){
                            db.user.update({"email":usuario.email},{"lastLogin":moment().unix()});
                        }
                        res.json(result);
                    })
                }
            });
        }
    });

    https.createServer({
        cert: fs.readFileSync('./cert/cert.pem'),
        key: fs.readFileSync('./cert/key.pem'),
    },app).listen(port,function(){
            console.log(`API Auth con MongoDB para Sistemas Distribuidos v1.0.0 ejecutándose en https://localhost:${port}/api/:coleccion/:id`);
    });
